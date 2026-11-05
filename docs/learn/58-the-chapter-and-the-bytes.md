# Lesson 58: The chapter and the bytes

This lesson goes with P5b Task 7. That task changed no code. It rewrote the body
chapter of `docs/CRYPTO.md` for body schema 2, and tied that chapter to a test.

## Why this matters

A file format has two descriptions. One is the code that writes it. The other is the
page that a reviewer reads, or that someone uses to write a second reader. If the two
drift apart, the reviewer checks the wrong thing, and nobody notices until a file
fails to open.

Holm ties the page to the code with one fixture. `docs/CRYPTO.md` quotes the 51 bytes
of a new, empty vault body. The test `default_body_golden` holds the same 51 bytes as
`V1_DEFAULT_GOLDEN`, and checks the writer against them byte for byte. If the format
changes, the test fails. The fix is then a schema bump plus an edit to the page, not a
quiet edit to the test.

There is a second fixture: the sealed golden vault in `tests/golden_vault.rs`. It is a
whole encrypted file, built with fixed key material, holding the schema-1 body. It
stays schema 1 on purpose. It is the proof that a vault written before schema 2 still
opens. If we rebuilt it as schema 2, we would throw away the only test that an old
file opens. Opening a vault and saving it writes schema 2. The golden test opens and
never saves, so the file on disk never changes.

## What we built

- A new "schema v2" chapter in `docs/CRYPTO.md`:
  - the version byte, then postcard;
  - version 1 read with the old wire structs, then written back as version 2;
  - `NewerSchema` above 2, and `UnknownSchema` for 0;
  - the wire order of a custom field (position, label, value, expiry);
  - which bad input is `Malformed` and which is `Invalid`;
  - the size budget, UTC dates, and the 51 golden bytes.
- The import and export section of `docs/CRYPTO.md` now covers the 54 columns, the
  slot rules and `Session::export_json`.
- One sentence in `fuzz/README.md`: a version-1 body re-encodes as version 2, so
  `decode_body` checks that the second encode matches the first, not that the input
  comes back.

## Rust ideas in this task

### A byte array as a spec

```rust
#[rustfmt::skip]
const V1_DEFAULT_GOLDEN: [u8; 51] = [
    1, 0,                         // schema version 1, little-endian
    172, 2, 30, 1,                // auto-lock 300 (varint), clipboard 30, lock on sleep
    20, 1, 1, 1, 1, 0, 1, 1,      // password: length 20, sets, no look-alike filter, minimums
    // ...
    0,                            // no items
    4,                            // next category id
];
```

The type `[u8; 51]` puts the length in the type. Add or drop a byte and the program
does not compile. `#[rustfmt::skip]` keeps one line per piece of the format, so the
comments line up with the bytes they describe.

`172, 2` is 300 as a postcard varint. The low 7 bits of 300 are 44. The top bit is set
to say "more bytes follow", so the first byte is 44 + 128 = 172. Then 300 >> 7 = 2.

In Kotlin you'd write `val V1_DEFAULT_GOLDEN = byteArrayOf(1, 0, 172.toByte(), 2, ...)`.
Kotlin bytes are signed, so 172 needs `toByte()`. The length is not part of the type.

### Reading the version without indexing

```rust
let (version, rest) = plaintext
    .split_first_chunk::<VERSION_LEN>()
    .ok_or(BodyError::TooShort)?;
let version = u16::from_le_bytes(*version);
```

`split_first_chunk` returns `None` when the slice is shorter than 2 bytes, so there is
no index that can panic. `version` is a `&[u8; 2]`, which is exactly what
`from_le_bytes` takes.

In Kotlin you'd write
`ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).short`, and catch a
`BufferUnderflowException` for a short buffer.

### Constants as match patterns

```rust
reject_if_newer(version, BODY_SCHEMA_VERSION)?;
let mut data = match version {
    BODY_SCHEMA_V1 => { /* BodyInV1, fields empty */ }
    BODY_SCHEMA_VERSION => { /* BodyIn */ }
    _ => return Err(BodyError::UnknownSchema(version)),
};
```

A `const` can be a pattern. `reject_if_newer` has already refused 0 and anything above
2, so the `_` arm is a guard that should never run. The page says the same thing: above
2 is `NewerSchema`, and 0 is `UnknownSchema`.

In Kotlin you'd write `when (version) { BODY_SCHEMA_V1 -> ...; BODY_SCHEMA_VERSION -> ...; else -> throw ... }`.

### Arrays are Copy

```rust
let encoded = bytes(&VaultData::new_default());
let mut expected = V1_DEFAULT_GOLDEN;
expected[0] = 2;
assert_eq!(encoded, expected);
```

`let mut expected = V1_DEFAULT_GOLDEN;` copies all 51 bytes, because `[u8; N]` is
`Copy`. Changing byte 0 does not touch the constant. This one test is the whole
statement "the version-2 empty body is the version-1 body with byte 0 set to 2".

In Kotlin you'd write `val expected = V1_DEFAULT_GOLDEN.copyOf().also { it[0] = 2 }`.
Without `copyOf()`, Kotlin would change the shared array.

### A writer that exists only in tests

```rust
#[cfg(test)]
fn encode_v1_for_test(data: &VaultData) -> SecretBuf {
    // BodyOutV1, written under version byte 1
}
```

Holm must never write version 1 again, but the tests need version-1 bytes to prove
they still open. `#[cfg(test)]` removes the function from every normal build, so no
shipping code can call it.

In Kotlin you'd put the helper in the `test` source set. `cfg` goes further: the code
is not in the release binary at all.

## Exercises

1. Work out the varint for an auto-lock of 600 seconds by hand. Then write a test in
   `body.rs` named `auto_lock_600_bytes`. It sets `settings.auto_lock_secs = 600` on
   `VaultData::new_default()`, encodes it, and checks bytes `2..4`. (Hint: the low 7
   bits of 600 are 88.)
   `cargo test -p holm-core --locked --lib auto_lock_600_bytes`

2. Change the `20` (password length) in `V1_DEFAULT_GOLDEN` to `21` and run the golden
   test. Read the failure. Which assertion fails first, the encode compare or the
   decode? Why does the decode on its own not catch it? Put the `20` back afterwards.
   `cargo test -p holm-core --locked --lib body::tests::default_body_golden`

3. Write a test named `schema_byte_exercise`. It copies `V1_DEFAULT_GOLDEN`, sets byte 0
   to 3, and checks that `VaultData::decode` returns `NewerSchema(3)`. Then also set
   byte 1 to 1. Predict the version number before you run it.
   `cargo test -p holm-core --locked --lib schema_byte_exercise`

## Read next

- The Rust Book, [Writing automated tests](https://doc.rust-lang.org/book/ch11-01-writing-tests.html)
  and [Test organization](https://doc.rust-lang.org/book/ch11-03-test-organization.html),
  for `#[cfg(test)]`.
- The Rust Book, [The match control flow construct](https://doc.rust-lang.org/book/ch06-02-match.html).
- [Lesson 13](13-serde-and-versioned-formats.md) for the first version prefix, and
  [Lesson 52](52-a-second-schema.md) for why schema 2 is a second struct.
- `docs/CRYPTO.md`, "The vault body (schema v2)", next to `body.rs`.
