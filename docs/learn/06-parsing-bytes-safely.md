# Lesson 06: Parsing bytes safely

## What we built

`crates/holm-core/src/format.rs` holds the v1 vault header: 164 fixed bytes at the start of every vault file. `Header::encode` writes them. `Header::parse` reads a whole file, checks every byte it is allowed to check, and hands back the header plus the body ciphertext. It never panics, whatever bytes it gets.

The parser reads hostile input. Anyone who can edit the file can edit the header, so each field is checked before it is trusted.

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
- `try_into()` turns a `&[u8]` slice into a `[u8; N]` array. It fails if the length is wrong.

In Kotlin you'd write: `bytes.getOrNull(i)` and `copyOfRange`, which throws `IndexOutOfBoundsException`. Rust makes you pick the non-throwing path on purpose. ([slice::get](https://doc.rust-lang.org/std/primitive.slice.html#method.get), [checked_add](https://doc.rust-lang.org/std/primitive.u64.html#method.checked_add))

### 2. Const generics

`read_array::<3>(head, OFF_RESERVED)` asks for exactly three bytes. `N` is part of the type, so the compiler knows the array size. ([Const generics](https://doc.rust-lang.org/reference/items/generics.html#const-generics))

### 3. Little-endian integers

`u32::from_le_bytes([u8; 4])` and `to_le_bytes()` convert between numbers and bytes with a fixed byte order. The file looks the same on every CPU. In Kotlin, `ByteBuffer.order(LITTLE_ENDIAN).getInt()`. ([from_le_bytes](https://doc.rust-lang.org/std/primitive.u32.html#method.from_le_bytes))

### 4. `usize::try_from` for lengths from the file

```rust
let body_len_usize = usize::try_from(body_len).map_err(|_| FormatError::LengthMismatch)?;
let total = HEADER_LEN.checked_add(body_len_usize).ok_or(FormatError::LengthMismatch)?;
```

The length field is a `u64` chosen by the attacker. `as usize` would silently truncate on a 32-bit machine. `try_from` fails loudly. Then `checked_add` guards the sum. ([TryFrom](https://doc.rust-lang.org/std/convert/trait.TryFrom.html))

### 5. Error enums with `thiserror`

```rust
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),
    #[error("key-derivation costs refused: {0}")]
    KdfPolicy(KdfParamsError),
    // ...
}
```

Each failure is its own variant, so tests (and the UI) can tell them apart. `#[error("...")]` writes the `Display` text. `KdfPolicy` wraps the error from `holm-crypto`, so the cost caps live in one place only. Messages carry numbers like the version, never file contents. ([thiserror](https://docs.rs/thiserror))

### 6. Returning a borrowed slice

```rust
pub fn parse(file: &[u8]) -> Result<(Header, &[u8]), FormatError>
```

The returned body points into `file`. No copy. The elided lifetime ties the output to the input, so the compiler stops you from using the body after `file` is gone. Kotlin would copy or use a view; Rust proves the view is safe. (See lesson 05.)

## Why this matters for security

- Check order: cheap checks first (size, magic, version, flags, KDF id, reserved), then the KDF cost policy, and only later would a caller derive a key. A forged header cannot demand 64 GiB of RAM.
- Reserved bytes must be zero. Otherwise an attacker can flip them and we would accept the file, so two different byte strings would mean the same vault.
- There is no CRC. The AEAD tag is the integrity check, and the first 60 bytes (wrap AAD) and all 164 bytes (body AAD) feed into it, so any header edit breaks decryption.
- A parser that panics is a denial of service. A test parses a truncated file at every length from 0 to 163 to prove it does not.

## Try it

1. In `format.rs`, change `FORMAT_VERSION` to `2` and run `cargo test -p holm-core format`.
   Check: the roundtrip test still passes (encode and parse share the constant) but `unsupported_version_rejected` fails, because version 2 is now valid. Tests catch what the constant alone hides.
   Undo: `git checkout crates/holm-core/src/format.rs`
2. Replace the `read_array` body with `Some(bytes[offset..offset + N].try_into().unwrap())` and run the truncation test.
   Check: it panics. That is the bug the real code avoids.
   Undo: `git checkout crates/holm-core/src/format.rs`

## Read next

Lesson 07: sealing and opening the body with the header as AAD.
