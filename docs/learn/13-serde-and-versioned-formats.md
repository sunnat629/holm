# Lesson 13: Serde and a versioned binary format

## What we built

The envelope from lesson 07 encrypts a body, and this task decides what those bytes are. `body::VaultData` holds the settings, categories, items and next category id, and `encode` and `decode` turn it into bytes and back. The layout is a 2-byte little-endian schema version, then the [`postcard`](https://docs.rs/postcard) encoding of the four fields. `settings::Settings` holds auto-lock (60 to 3,600 s), clipboard clearing (5 to 90 s), lock on sleep and the generator defaults, inside the encrypted body so nobody can weaken them by editing a file. The code is in `settings.rs`, `body.rs` and `wire.rs` under `crates/holm-core/src/`.

## Rust ideas in this task

### Serde derive, on private types only

```rust
#[derive(Serialize)]
pub(crate) struct BodyOut<'a> {
    pub(crate) settings: SettingsWire,
    pub(crate) categories: Vec<CategoryOut<'a>>,
    pub(crate) items: Vec<ItemOut<'a>>,
    pub(crate) next_category_id: u32,
}
```

- `serde` splits the job in two. `#[derive(Serialize)]` writes code that walks a struct field by field. A *format* crate such as postcard or serde_json decides what bytes each field becomes. One derive works with every format.
- `Item`, `Settings` and the text types have **no** serde derive. If they did, any crate that uses Holm could call `serde_json::to_string(&item)` and print a password. Only the `pub(crate)` wire types in `wire.rs` derive serde, and `compile_fail` doctests in `lib.rs` prove the public types cannot be serialised.
- `BodyOut<'a>` borrows: its fields are `&'a str` slices pointing into the real items. Writing a body never makes a second copy of a password in a `String`.

In Kotlin you'd write: `@Serializable data class Item(...)` with kotlinx.serialization. That puts the serializer on the public class. Here the public class stays closed and a private DTO does the work, like a separate `ItemDto` that only your persistence layer can see.

### A format that does not describe itself

```text
1, 0,           schema version 1
172, 2, 30, 1,  auto-lock 300, clipboard 30, lock on sleep
...
3,              3 categories
1, 8, P e r s o n a l, ...
```

- JSON writes field names, so a reader can skip a field it does not know. Postcard writes only values, in declaration order, with integers as varints (7 bits per byte, the top bit means "more"). 300 is `172, 2`.
- That makes the file small and the parser simple, but the *order of the fields is the format*. Swapping two fields in `BodyOut` would silently change every vault. The `default_body_golden` test pins the 51 bytes of a new vault, so any such change fails the build.
- A reader cannot skip unknown data, so a newer Holm that adds a field must bump the schema version.

In Kotlin you'd write: `ProtoBuf.encodeToByteArray(value)` from kotlinx.serialization. Protobuf keeps field numbers; postcard does not even keep those.

### A version prefix, and refusing the future

```rust
let (version, rest) = plaintext
    .split_first_chunk::<VERSION_LEN>()
    .ok_or(BodyError::TooShort)?;
let version = u16::from_le_bytes(*version);
if version > BODY_SCHEMA_VERSION {
    return Err(BodyError::NewerSchema(version));
}
```

- `split_first_chunk::<2>()` returns `Option<(&[u8; 2], &[u8])>`: a fixed-size array and the rest. No index can go out of bounds, so no panic.
- A body from a newer Holm is refused, not decoded as best we can. If an old Holm opened it, it would drop the fields it does not know and then save, and the user's new data would be gone.
- Version 0 was never written, so it gets its own error, `UnknownSchema(0)`.

In Kotlin you'd write: `val version = buf.order(LITTLE_ENDIAN).short` and a `require(version <= CURRENT)`. Same idea, but `ByteBuffer` throws on a short read where Rust makes you handle the `None`.

### Decode, then validate, and bound everything while parsing

```rust
fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
    let hint = seq.size_hint().unwrap_or(0);
    if hint > MAX {
        return Err(de::Error::invalid_length(hint, &self));
    }
    let mut v = Vec::with_capacity(hint.min(PREALLOC_CAP));
    ...
}
```

- Decoding happens in two stages. First postcard turns bytes into wire structs (`BodyIn`, `ItemIn`). Then each wire struct is converted into a real `Item`, and the conversion runs `validate_item`: the same function the add and update paths use. Last come the cross-checks: unique item ids, unique category names, every item's category exists.
- Postcard writes a list as a length and then the elements. A crafted body can claim 2^40 categories in 6 bytes. `BoundedVec<T, MAX>` refuses a length above its cap before reading a single element, and reserves at most 1,024 slots up front. Strings have a cap too (64 KiB). The `huge_length_prefix_no_alloc` test checks this.
- `const MAX: usize` is a *const generic*: the cap is part of the type, so `BoundedVec<ItemIn, MAX_ITEMS>` and `BoundedVec<WireStr, MAX_URLS>` are two different types with no runtime field.

In Kotlin you'd write: a custom `KSerializer` whose `deserialize` checks `decodeCollectionSize()` before building the list. Most Kotlin code trusts the size, and so does serde's default `Vec` impl up to 1 MiB.

### Why trailing bytes are rejected

```rust
let (wire, leftover) = postcard::take_from_bytes::<BodyIn>(rest).map_err(|_| BodyError::Malformed)?;
if !leftover.is_empty() {
    return Err(BodyError::Malformed);
}
```

- `take_from_bytes` returns the value and the unread rest. Holm insists the rest is empty. Extra bytes mean a buggy writer or a body from a format we do not understand, and ignoring them would hide data that could later be lost on save.
- Encode is deterministic: one vault always gives the same bytes, so the golden test pins the writer. Decode is not canonical. Postcard accepts an overlong varint (`158, 0` reads as 30), and clamping maps clipboard 0 and 5 to the same setting. That is fine because the body is AEAD-authenticated and Holm always re-encodes canonically, but never compare body bytes to detect a change.

In Kotlin you'd write: `ProtoBuf.decodeFromByteArray(bytes)`, which ignores trailing data, so you would decode from a stream and check `input.available() == 0` yourself.

### Measure before you allocate

```rust
let size = postcard::serialize_with_flavor(&out, postcard::ser_flavors::Size::default())
    .map_err(|_| BodyError::Encode)?;
let total = size.checked_add(VERSION_LEN).ok_or(BodyError::Encode)?;
let mut buf = Zeroizing::new(vec![0u8; total]);
let (version, rest) = buf.split_at_mut(VERSION_LEN);
version.copy_from_slice(&BODY_SCHEMA_VERSION.to_le_bytes());
let written = postcard::to_slice(&out, rest).map_err(|_| BodyError::Encode)?.len();
// written == size, checked in the real code
Ok(SecretBuf::from_vec(core::mem::take(&mut *buf)))
```

- The `Size` *flavor* runs the serializer but only counts bytes. Then one zeroed buffer of exactly that size is allocated inside `Zeroizing`, and `to_slice` writes into it.
- A plain `to_allocvec` would grow a `Vec` while writing. Each time a `Vec` grows it moves to a bigger allocation and frees the old one without wiping it, leaving pieces of every password in freed memory. Measuring first means there is never a smaller copy.
- `core::mem::take` moves the `Vec` out (pointer, length, capacity) and leaves an empty one behind. The bytes are not copied; `SecretBuf` wipes them when it drops.

In Kotlin you'd write: `ByteArray(size)` then `ByteBuffer.wrap(arr).put(...)`, with `arr.fill(0)` in a `finally`. The JVM may still have copied the array during garbage collection, which Rust never does.

## Why this matters for security

The body is the vault, and once the AEAD tag checks out the rest of Holm trusts it, so the decoder is the last gate. It treats its input as hostile: a bug in an older writer, or a future one, must give an error, never a panic, a huge allocation, or an item that breaks the field rules (such as a title with a right-to-left override that disguises `exe` as `txt`).

`encode` runs the same checks before it writes, so Holm cannot save a body it would refuse to open. Settings are the one exception on the way in: an out-of-range value in an authenticated body is clamped into range, not refused (`docs/DECISIONS.md`), so a vault never becomes unopenable over a setting.

## Try it

1. Run the body and settings tests.
   - Run: `cargo test -p holm-core --locked --lib body::tests`, then `cargo test -p holm-core --locked --lib settings::tests`
   - Check: the first `test result:` line says `ok. 23 passed`, the second `ok. 4 passed`.
   - Undo: nothing to undo, it only reads.
2. Change a default and watch the golden vector catch it.
   - Run: `sed -i.bak 's/AUTO_LOCK_DEFAULT_SECS: u32 = 300/AUTO_LOCK_DEFAULT_SECS: u32 = 600/' crates/holm-core/src/settings.rs && cargo test -p holm-core --locked --lib default_body_golden`
   - Check: `default_body_golden ... FAILED`. The left side starts `[1, 0, 216, 4, ...]`: 600 as a varint is `216, 4`.
   - Undo: `rm crates/holm-core/src/settings.rs.bak && git checkout -- crates/holm-core/src/settings.rs`. Do not `mv` the `.bak` back: it keeps its old timestamp, so cargo thinks the 600 build is still fresh.
3. See where cargo vet's trust in postcard comes from.
   - Run: `grep -A3 'audits.bytecode-alliance.audits.postcard' supply-chain/imports.lock`, then `cargo vet --locked`
   - Check: two imported audits, `safe-to-deploy`, for `1.0.8` and the delta `1.0.8 -> 1.1.3`; then `Vetting Succeeded`. There is no audit of our own.
   - Undo: nothing to undo, it only reads.

## Read next

- [The Rust book, ch10-01: generic data types](https://doc.rust-lang.org/book/ch10-01-syntax.html), the base for const generics like `BoundedVec<T, MAX>`.
- [serde::de::Visitor](https://docs.rs/serde/latest/serde/de/trait.Visitor.html)
- [postcard::ser_flavors::Size](https://docs.rs/postcard/latest/postcard/ser_flavors/struct.Size.html)

Next lesson: [14, time and saturating maths](14-time-and-saturating-maths.md).
