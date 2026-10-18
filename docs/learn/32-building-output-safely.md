# Lesson 32: Building output safely

## Why this matters

A CSV export is the one file where Holm writes every password in plain text, on purpose, because
the user asked. Holm cannot make that file safe once it exists. What it can do is not leave extra
copies in memory while building it, never overwrite or follow something already at the path, make
the file readable by its owner only, and write the bytes exactly as they are in the vault.

## What we built

`crates/holm-core/src/export.rs` adds `Session::export_csv`. It checks the master password again
through the throttle, takes every item outside the Trash in list order, and builds the CSV in one
buffer of the exact final size. `crates/holm-platform/src/private_file.rs` adds
`write_new_private_file`, which creates a new owner-only file and removes it if the write fails,
and `read_capped`, which reads an import file only if it is a regular file under the size cap. The
on-disk round trip test now exports, writes the file, reads it back and imports it into a new vault.

## Rust ideas in this task

### 1. Measure, then fill

```rust
let mut total = row_len(&EXPORT_COLUMNS);
for item in items {
    total = total.saturating_add(with_cells(item, categories, row_len));
}
let mut out = Zeroizing::new(String::with_capacity(total));
push_row(&mut out, &EXPORT_COLUMNS);
for item in items {
    with_cells(item, categories, |cells| push_row(&mut out, cells));
}
assert_eq!(out.len(), total, "export measure and fill disagree");
```

A `String` that runs out of room allocates a bigger buffer, copies the bytes over and frees the
old one. `Zeroizing` wipes only the buffer it owns at drop time, so the freed one keeps a copy of
every password written so far. Walking the items twice (once to add up the length, once to write)
costs a little time and leaves no copy. `push_quoted` and `push_fitting` both `assert!` there is
room before they write, in release builds too, so a measuring bug panics instead of reallocating.

At the end, `mem::take(&mut *out).into_bytes()` moves the heap buffer into a `SecretBuf` without
copying a byte.

In Kotlin you'd write `StringBuilder(capacity)`, but a `StringBuilder` grows silently when you
guess low, and the garbage collector frees the old array without wiping it. Rust lets you check.

### 2. Quote every cell

```rust
pub(crate) fn quoted_len(cell: &str) -> usize {
    let quotes = cell.bytes().filter(|&b| b == b'"').count();
    cell.len().saturating_add(quotes).saturating_add(2)
}
```

RFC 4180 says a cell may be wrapped in `"`, and inside it a `"` is written twice. Commas, `\n`
and `\r\n` inside quotes are part of the cell. Holm quotes every cell, not just the ones that
need it, so one rule covers a password with a comma, a note with line breaks and a title with a
quote. `quoted_len` is that rule as a length: the cell, one more byte per `"`, and two quotes.
The test `export_quotes_everything` pins the exact bytes.

In Kotlin you'd write `"\"" + cell.replace("\"", "\"\"") + "\""`, which builds two new strings per
cell. Here nothing is built: the bytes go straight into the one buffer.

### 3. A file nobody else can open, created new

```rust
let mut options = OpenOptions::new();
options.write(true).create_new(true);
#[cfg(unix)]
{
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}
options.open(path)
```

`create_new(true)` asks the OS for `O_CREAT | O_EXCL`: fail if anything is at the path. That
includes a symlink, even one whose target does not exist, so an attacker cannot plant a link that
makes Holm write the passwords somewhere else. `mode(0o600)` sets the permissions at creation, so
there is no moment where the file is readable by others. `OpenOptionsExt` is a Unix-only
extension trait, which is why it is imported inside the `cfg` block.

If the write or `sync_all` fails, `write_new_private_file` removes the file, so a half-written
export does not sit on disk. The test `failed_write_removes_partial_file` passes in a writer that
writes three bytes and then fails.

In Kotlin you'd write
`Files.newOutputStream(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)` and set
`PosixFilePermissions` through a `FileAttribute` at creation, not afterwards.

### 4. Reading back without trusting the file

```rust
let len = checked_len(&fs::metadata(path).map_err(io_err)?, max)?;
let file = open_for_read(path).map_err(io_err)?;
let len_now = checked_len(&file.metadata().map_err(io_err)?, max)?;
// ...
reader.read_exact(&mut bytes).map_err(io_err)?;
match reader.read(&mut probe) {
    Ok(0) => return Ok(bytes),
    Ok(_) => return Err(StoreError::Io(ErrorKind::InvalidData)),
    // ...
}
```

`read_capped` checks the size before it opens anything, opens with `O_NONBLOCK` so a FIFO cannot
hang it, checks again on the handle it really reads, and reads exactly that many bytes into one
`Zeroizing<Vec<u8>>`. One more read must return 0; if it returns a byte, the file grew and the
parsed bytes would not be the bytes whose size was checked.

In Kotlin you'd write `Files.readAllBytes(path)`, which has no cap and blocks on a FIFO.

### 5. Why there is no formula escaping

Spreadsheet apps run a cell that starts with `=`, `+`, `-` or `@` as a formula. Some exporters put
a `'` in front. Holm does not: `=SUM(A1)` can be a real password, and changing it would break the
import back into Holm or into another manager. Instead the warning says not to open the file in a
spreadsheet app, and the user must type the master password and confirm. The test
`export_does_not_escape_formulas` checks that all four come back byte-exact.

## Exercises

1. Change `String::with_capacity(total)` in `build` to `String::with_capacity(total - 1)` and run
   the tests. Read which assert fires and why that is better than a silent reallocation. Then undo
   it. Check: `cargo test -p holm-core --locked export_buffer_allocated_once`
2. Add a test that `write_new_private_file` refuses a path inside a folder that does not exist
   with `StoreError::Io(ErrorKind::NotFound)` and creates nothing. Check:
   `cargo test -p holm-platform --locked write_new_private_file`
3. Write a test that exports a login whose notes are `"a\r\nb"` and checks that the CSV holds
   `"a\r\nb"` inside quotes and imports back unchanged. Check:
   `cargo test -p holm-core --locked export_`

## Read next

- [std::fs::OpenOptions::create_new](https://doc.rust-lang.org/std/fs/struct.OpenOptions.html#method.create_new)
- [RFC 4180: Common Format for CSV Files](https://www.rfc-editor.org/rfc/rfc4180)
- [Lesson 30: Parsing untrusted text](30-parsing-untrusted-text.md)
