# Lesson 06: Parsing bytes safely

## What we built

`crates/holm-core/src/format.rs` holds the v1 vault header: 164 fixed bytes at the start of every vault file. `Header::encode` writes them. `Header::parse` reads a whole file, checks every byte it is allowed to check, and hands back the header plus the body ciphertext. It never panics, whatever bytes it gets.

The parser reads hostile input, because anyone who can edit the file can edit the header.

## Rust ideas in this task

### 1. `get` instead of indexing

```rust
fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    bytes.get(offset..end)?.try_into().ok()
}
```

Line by line:
- `bytes[a..b]` panics if the range is out of bounds. `bytes.get(a..b)` returns `None` instead.
- `checked_add` returns `None` on overflow, where `+` would wrap in release builds or panic in debug builds.
- `?` returns early with `None` from the function.
- `try_into()` turns the `&[u8]` slice into a `[u8; N]` array. It returns a `Result` that fails if the length is wrong, and `.ok()` converts that `Result` to an `Option`, which is what this function returns.

In Kotlin you'd write: `bytes.getOrNull(i)` for one element, or `copyOfRange(a, b)`, which throws `IndexOutOfBoundsException`. Rust lets you pick the non-throwing path. ([slice::get](https://doc.rust-lang.org/std/primitive.slice.html#method.get), [usize::checked_add](https://doc.rust-lang.org/std/primitive.usize.html#method.checked_add), [The Slice Type](https://doc.rust-lang.org/book/ch04-03-slices.html))

### 2. Const generics

```rust
let reserved = read_array::<3>(head, OFF_RESERVED).ok_or(FormatError::TooShort)?;
if reserved != [0; 3] {
    return Err(FormatError::ReservedNotZero);
}
```

Line by line:
- `read_array::<3>` fills in `N = 3`. `N` is a number that is part of the function's type, the way `T` is a type in `List<T>`.
- The result is `[u8; 3]`: an array whose length the compiler knows.
- `reserved != [0; 3]` compares it with three zero bytes. Arrays of the same length compare element by element.
- In `salt: read_array(head, OFF_SALT)`, nobody writes `N`: the compiler infers 32 from the type of the `salt` field.

In Kotlin you'd write: `fun readBytes(b: ByteArray, off: Int, n: Int): ByteArray`. The size is a run-time argument and the return type is always `ByteArray`, so a wrong size is found only when the code runs. ([Const generics](https://doc.rust-lang.org/reference/items/generics.html#const-generics), [Generic data types](https://doc.rust-lang.org/book/ch10-01-syntax.html))

### 3. Little-endian integers

```rust
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    read_array(bytes, offset).map(u32::from_le_bytes)
}
```

Line by line:
- `read_array` returns `Option<[u8; 4]>`; the compiler infers 4 because `u32::from_le_bytes` takes `[u8; 4]`.
- `.map(f)` applies `f` to the value inside `Some` and leaves `None` alone.
- `from_le_bytes` reads the four bytes with the least significant byte first. `encode` uses the matching `to_le_bytes`, so the file looks the same on every CPU.

In Kotlin you'd write: `ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getInt(off)`. Forget `.order(...)` and Java uses big-endian. In Rust the byte order is in the function name. ([from_le_bytes](https://doc.rust-lang.org/std/primitive.u32.html#method.from_le_bytes), [Option::map](https://doc.rust-lang.org/std/option/enum.Option.html#method.map))

### 4. `usize::try_from` for lengths from the file

```rust
let body_len_usize = usize::try_from(body_len).map_err(|_| FormatError::LengthMismatch)?;
if body_len_usize < TAG_LEN {
    return Err(FormatError::BodyTooShort);
}
let total = HEADER_LEN
    .checked_add(body_len_usize)
    .ok_or(FormatError::LengthMismatch)?;
if total != file.len() {
    return Err(FormatError::LengthMismatch);
}
```

Line by line:
- `body_len` is a `u64` the attacker chose. `as usize` would silently cut it down on a 32-bit machine. `usize::try_from` returns `Err` instead.
- `map_err` swaps the library's error for ours. The `|_|` closure ignores the original error.
- `?` returns our error from `parse` if the conversion failed.
- The `if` rejects a body too short to hold even the 16-byte tag.
- `checked_add` guards the sum, and the last `if` demands that header plus body is exactly the file size, so truncated files and trailing bytes both fail.

In Kotlin you'd write: `val n = bodyLen.toInt()`, which silently wraps for big values. `Math.toIntExact(bodyLen)` is the checked form, and it throws. Rust's `Result` makes you handle the failure at the call site. ([TryFrom](https://doc.rust-lang.org/std/convert/trait.TryFrom.html), [Result::map_err](https://doc.rust-lang.org/std/result/enum.Result.html#method.map_err))

### 5. `match` on enums

`parse` returns `Result<_, FormatError>`, and `FormatError` is an enum with one variant per failure. A caller (the UI, later) will look at which variant came back with `match`. This is an illustrative example, not code from `format.rs`, because the library itself only builds the errors:

```rust
fn user_message(err: &FormatError) -> &'static str {
    match err {
        FormatError::TooLarge | FormatError::TooShort => "This is not a Holm vault.",
        FormatError::UnsupportedVersion(v) if *v > 1 => "This vault is from a newer Holm.",
        FormatError::UnsupportedVersion(_) => "This vault version is not supported.",
        FormatError::KdfPolicy(_) => "This vault asks for more resources than allowed.",
        _ => "This vault file is damaged.",
    }
}
```

Line by line:
- `match err` checks the value against each arm from top to bottom and runs the first one that fits.
- `A | B` lets one arm cover two variants.
- `UnsupportedVersion(v)` pulls the number out of the variant and names it `v`. `if *v > 1` is a guard: the arm applies only when it holds. `v` is a reference here, hence `*v`.
- `KdfPolicy(_)` matches the variant and ignores what is inside.
- `_` catches every remaining variant. Leave it out and the compiler lists the variants you forgot. That is the main benefit: add a new error later and every `match` without `_` stops compiling until you handle it.

In Kotlin you'd write: `when (err) { is FormatError.TooLarge, is FormatError.TooShort -> ... }` over a `sealed class`. It is close. The Rust difference is that variants carry data natively and the check is always exhaustive. ([Enums and match](https://doc.rust-lang.org/book/ch06-02-match.html))

### 6. Error enums with `thiserror`

```rust
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),
    #[error("this vault's key-derivation settings are outside Holm's policy: {0}")]
    KdfPolicy(KdfParamsError),
    // ...
}
```

Line by line:
- `derive(Debug, Clone, PartialEq, Eq)` generates printing, copying and comparison, so tests can write `assert_eq!(err, FormatError::BadMagic)`.
- `thiserror::Error` generates the `Display` text from each `#[error("...")]`. `{0}` is the first field of the variant.
- `KdfPolicy(KdfParamsError)` wraps the error from `holm-crypto`, so the cost limits live in one place only.
- Messages carry numbers such as the version, never secrets or key material.

In Kotlin you'd write: `sealed class FormatError(message: String) : Exception(message)` with subclasses. Rust's version is a plain value, returned in a `Result`, not thrown. ([thiserror](https://docs.rs/thiserror), [Recoverable errors with Result](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html))

### 7. Returning a borrowed slice

```rust
pub fn parse(file: &[u8]) -> Result<(Header, &[u8]), FormatError>
```

Line by line:
- `file: &[u8]` borrows the bytes. `parse` does not own them.
- The second tuple element is `&[u8]`: the body. It points into `file`. No copy is made.
- There is one input reference, so the compiler gives the output the same lifetime without being asked (lifetime elision). The body cannot outlive `file`.

In Kotlin you'd write: `fun parse(file: ByteArray): Pair<Header, ByteArray>` with `copyOfRange(164, file.size)`, a copy, or a `ByteBuffer.slice()` view with no guarantee about who owns the memory. Rust proves the view is safe at compile time. (See lesson 05. [Validating references with lifetimes](https://doc.rust-lang.org/book/ch10-03-lifetime-syntax.html))

## Why this matters for security

- Cheap checks run first (size, magic, version, flags, KDF id, reserved), then the KDF cost caps. A forged header cannot demand 64 GiB of RAM before a key is derived.
- Reserved bytes must be zero, so one header has exactly one byte string.
- A parser that panics is a denial of service. A test parses a truncated file at every length to prove it does not.

## Try it

Run each one from the repo root. Undo after each: `git checkout crates/holm-core/src/format.rs`

1. In `format.rs`, change `FORMAT_VERSION` to `2` and run `cargo test -p holm-core format`.
   Check: 3 tests fail: `golden_bytes_encode`, `golden_bytes_parse` and `unsupported_version_rejected`. The round trip still passes, since encode and parse share the constant. Only the fixed golden bytes and the "version 2 is invalid" test catch the change.
2. Replace `let head = file.get(..HEADER_LEN).ok_or(FormatError::TooShort)?;` in `parse` with `let head = &file[..HEADER_LEN];` and run `cargo test -p holm-core truncated_header`.
   Check: the test panics with `range end index 164 out of range for slice of length 0`. This one guard is what makes every later read in `parse` safe, so removing it turns hostile input into a crash.
3. Add this test at the end of `mod tests` and run `cargo test -p holm-core reserved_byte_14`:

   ```rust
   #[test]
   fn reserved_byte_14_rejected() {
       assert_eq!(parse_err(&with_byte(14, 1)), FormatError::ReservedNotZero);
   }
   ```

   Check: it passes. Now delete the `if reserved != [0; 3] { ... }` block in `parse` and run it again. It now fails with `must be rejected: (Header { kdf: KdfParams { ... }, ... }, [9, 9, ...])`: `parse` returned `Ok` where the test expected an error, so the file was accepted. Undo as above.

## Read next

- *The Rust Programming Language* [chapter 6.2, The `match` Control Flow Construct](https://doc.rust-lang.org/book/ch06-02-match.html)
- [Chapter 9.2, Recoverable Errors with `Result`](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html)
- [Chapter 10.3, Validating References with Lifetimes](https://doc.rust-lang.org/book/ch10-03-lifetime-syntax.html)

Next: [Lesson 07, modules and encapsulation](07-modules-and-encapsulation.md).
