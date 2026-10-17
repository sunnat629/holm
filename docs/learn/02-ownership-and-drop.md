# Lesson 02: Ownership, Drop and secret types

## What we built

Three types in `crates/holm-crypto/src/secret.rs` that hold secrets with care:

- `SecretKey`: a 32-byte key. It lives on the heap inside a `Box`.
- `SecretBuf`: a secret byte buffer of any length.
- `MasterPassword`: the password text. `to_kdf_bytes()` turns it into the exact bytes the key-derivation step will use.

All three share four habits. They overwrite the memory they own with zeros when they are
dropped. They print `[REDACTED]` instead of their contents. They cannot be cloned or copied by
accident. And the password is normalised so the same letters always give the same bytes.
This reduces how long secrets sit in memory. It does not make memory "fully wiped"; the
limits section says why.

## Rust ideas in this task

### Ownership and moves, and why the key sits in a Box

Every value in Rust has exactly one owner. Assigning it or passing it to a function *moves*
it, and the old name stops working. A move copies the value's bytes to a new place. The real
line from `secret.rs`:

```rust
pub struct SecretKey(Box<[u8; 32]>);
```

Line by line: `pub struct SecretKey` declares a new type. The `( ... )` makes it a *tuple struct*
with one unnamed field, and because the field has no `pub`, code outside the module cannot
touch it. `Box<[u8; 32]>` is a pointer to 32 bytes on the heap. If the field were a plain
`[u8; 32]`, every move of the key would copy all 32 bytes and leave the old ones behind. With
a `Box`, a move copies only the pointer; the key bytes stay put.

In Kotlin you'd write: `class SecretKey(private val bytes: ByteArray)`. A `ByteArray` is
already a heap object that you pass around by reference, so moves never copy it. But Kotlin
has no "one owner" rule: any number of references can keep the array alive, and nothing stops
`bytes.copyOf()` anywhere.

([Understanding Ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html))

### Borrowing with `&mut`

```rust
pub fn from_bytes(bytes: &mut [u8; 32]) -> SecretKey {
    let mut key = SecretKey::zeroed();
    key.0.copy_from_slice(&bytes[..]);
    bytes.zeroize();
    key
}
```

Line by line:

- `bytes: &mut [u8; 32]` borrows the caller's array so we can change it, without taking it.
  Passing the array by value would copy it into the function's argument slot, a copy nobody
  can wipe.
- `let mut key = SecretKey::zeroed();` makes a key full of zeros. `mut` means we may change it.
- `key.0.copy_from_slice(&bytes[..])`: `.0` is the first (only) field, the box. We copy the
  caller's 32 bytes into the box, in place. `&bytes[..]` is a read-only view of the whole array.
- `bytes.zeroize();` overwrites the caller's array with zeros.
- `key` on the last line has no semicolon, so it is the return value. The key is *moved* out
  to the caller, and since it is boxed, only a pointer is copied.

In Kotlin you'd write: `fun fromBytes(bytes: ByteArray): SecretKey { val k = SecretKey(bytes.copyOf()); bytes.fill(0); return k }`.
Same idea, but Kotlin cannot promise that no other reference to `bytes` exists, and the JIT
may drop the `fill` as a pointless write. Rust's borrow rules guarantee that while we hold
`&mut`, nobody else is looking at the array.

([References and Borrowing](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html))

### Drop, derive and zeroize

```rust
#[derive(ZeroizeOnDrop)]
pub struct SecretKey(Box<[u8; 32]>);
```

`#[derive(...)]` asks the compiler to write a trait implementation for us. `ZeroizeOnDrop`
generates a `Drop` implementation. `Drop` is a trait whose `drop` method Rust calls when the
owner goes out of scope, including on early `return` and when a panic unwinds the stack. Our
generated `drop` overwrites the key bytes with the [`zeroize`](https://docs.rs/zeroize) crate,
which writes the zeros in a way the optimiser may not remove. (A plain "set to zero and never
read again" can be deleted by the compiler as a dead store.)

For the other two types we use a wrapper instead of a derive:

```rust
pub struct SecretBuf(Zeroizing<Vec<u8>>);
pub struct MasterPassword(Zeroizing<String>);
```

`Zeroizing<T>` holds a `T` and wipes it on drop. It wipes the spare capacity of the `Vec` or
`String` too, not just the used part.

In Kotlin you'd write: a `Closeable` with `override fun close() { bytes.fill(0) }`, used as
`SecretKey(...).use { ... }`. You must remember `use { }`, and the garbage collector decides
when memory is reused. In Rust the compiler inserts the `drop` call for you.

**What `Drop` does not promise.** Rust guarantees `Drop` runs *at most once*, not always.
It does not run if the value is leaked (`std::mem::forget`, `Box::leak`, a reference cycle in
`Rc`), or if the process ends without unwinding: `std::process::exit`, `abort`, a panic while
already panicking, `panic = "abort"`, or being killed by a signal. A moved value is dropped
where its *new* owner goes out of scope, not at the brace where it was created. So a program
that calls `process::exit` while holding a `MasterPassword` skips the wipe. Later tasks must
keep that in mind.

([The Drop Trait](https://doc.rust-lang.org/book/ch15-03-drop.html),
[Derivable Traits](https://doc.rust-lang.org/book/appendix-03-derivable-traits.html))

### Debug redaction

```rust
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}
```

Line by line: `impl fmt::Debug for SecretKey` says "here is how `SecretKey` prints with `{:?}`".
`fn fmt(&self, ...)` takes a read-only borrow of the key. `f` is the output being built.
`f.write_str(...)` writes a fixed string and never looks at the bytes. We write this by hand
because `#[derive(Debug)]` would print the bytes, straight into logs and panic messages.

In Kotlin you'd write: a `data class` generates `toString()` that prints every field, so
`data class SecretKey(val bytes: ByteArray)` leaks. The fix is a hand-written
`override fun toString() = "SecretKey([REDACTED])"`.

### Traits we leave out

```rust
static_assertions::assert_not_impl_any!(SecretKey: Clone, Copy);
```

`Clone` would make a second copy of the secret that also needs wiping, and `Copy` would make
copies silently on every assignment. We simply do not implement them, so `key.clone()` does
not compile. This line is in the `tests` module and checks that nobody adds them later. It
fails `cargo test` (the test build) if `SecretKey` ever implements `Clone` or `Copy`.

In Kotlin you'd write: nothing equivalent. Every object reference can be copied freely, and
`data class` even generates `copy()` for you.

### Unicode NFC and not reallocating

```rust
let cap = 3 * self.0.len();
let mut normalized = Zeroizing::new(String::with_capacity(cap));
normalized.extend(self.0.nfc());
```

Line by line:

- `self.0.len()` is the password length in bytes. NFC can grow UTF-8 by at most 3 times, so
  `cap` is a safe upper bound.
- `String::with_capacity(cap)` reserves that much room up front. A `String` that grows past its
  capacity moves to a bigger allocation and the old one is freed *without* being wiped.
  Reserving first means our buffer never reallocates.
- `Zeroizing::new(...)` wraps it so the buffer is wiped when it drops.
- `self.0.nfc()` is an iterator of characters in *Normalisation Form C*, from the
  [`unicode-normalization`](https://docs.rs/unicode-normalization) crate. `extend` appends them.

Why bother: "café" can be stored with one character `é` (U+00E9) or with `e` plus a
combining accent (U+0301). They look identical and have different bytes, and different
keyboards and operating systems produce different forms. Without NFC a user could be locked
out by typing the same password on another device. A test pins this down: both spellings give
the same bytes.

In Kotlin you'd write: `java.text.Normalizer.normalize(password, Normalizer.Form.NFC)`. It
returns a new immutable `String` that you can never wipe.

([Unicode UAX #15](https://unicode.org/reports/tr15/))

## Why this matters for security

On the JVM a password is often held in a `String`, which is immutable, so it cannot be
wiped and stays in the heap until the garbage collector reuses that memory. That is why Java guidance says to use `char[]`. In Rust
we can say precisely where a secret lives, who owns it, and when we try to wipe it.

Be honest about the limits. We wipe the memory our types own, and nothing more:

- Drop does not run on `mem::forget`, `Box::leak`, `process::exit`, `abort` or a kill signal (see above).
- The compiler may leave temporary copies on the stack or in CPU registers, for example while a key or password is being moved or compared. `zeroize` cannot reach those.
- The operating system can write memory to swap, hibernation files and crash dumps. We do not lock memory yet; that comes in Phase 4.
- The `String` the caller gives to `MasterPassword::new` (or the `Vec` given to `SecretBuf::from_vec`) may have been copied or reallocated before it reached us, for example by the terminal or the UI toolkit. We wipe only what we hold.
- The NFC normaliser keeps its own small scratch buffers. For unusual input (five or more stacked combining marks) they spill to the heap and are freed without a wipe. We cannot fix that without writing our own normaliser.
- The allocator may have kept copies from earlier reallocations that are not ours to find.

So never say "the password is fully wiped". Say "the buffers Holm owns are wiped on drop".

## Try it

1. Run `cargo test -p holm-crypto secret` and read the 12 test names. Which one proves the caller's array is wiped? Check: `cargo test -p holm-crypto from_bytes_wipes_source` shows `1 passed`.
2. In `secret.rs`, temporarily add `Clone` to a derive list on `SecretKey` (for example `#[derive(ZeroizeOnDrop, Clone)]`) and run `cargo test -p holm-crypto`. Read the error from the build, then undo it with `git checkout crates/holm-crypto/src/secret.rs`. Check: the test run must fail before you undo and pass after.
3. Write a test that builds `SecretBuf::from_vec(vec![1, 2, 3])` and asserts `len()` is 3 and `is_empty()` is false. Check: `cargo test -p holm-crypto <your test name>` shows `1 passed`.

## Read next

- [The Rust Programming Language, ch. 4: Understanding Ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html)
- [ch. 15.3: Running Code on Cleanup with the Drop Trait](https://doc.rust-lang.org/book/ch15-03-drop.html)
- [zeroize documentation](https://docs.rs/zeroize)
