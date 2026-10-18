# Lesson 10: Enums, newtypes and validation

## What we built

Holm now has the types that describe what a vault holds: items (logins, crypto addresses,
recovery phrases, secure notes), categories, and the text wrappers they are made of. Plain
text uses `Text`, secrets use `SecretText`, and both wipe their memory when dropped. One
enum, `ItemData`, holds the four kinds of item, and one function checks the field rules for
all of them. When a rule fails, the error names the field and never contains the value.

## Rust ideas in this task

### Enums that carry data

```rust
pub enum ItemData {
    Login { username: Text, password: SecretText, urls: Vec<Text>, notes: SecretText },
    CryptoAddress { chain: Text, address: SecretText, memo: SecretText, notes: SecretText },
    RecoveryPhrase { phrase: GatedSecret, notes: SecretText },
    SecureNote { body: SecretText },
}
```

- Each variant has its own fields. A `SecureNote` has no `password`, so you cannot set one by mistake.
- The enum is one type, so an `Item` holds exactly one `ItemData` and the compiler knows which shape it has.

In Kotlin you'd write: a `sealed interface ItemData` with a `data class Login(...)`, a `data class CryptoAddress(...)` and so on as subclasses.

### `match` must cover every variant

```rust
pub fn item_type(&self) -> ItemType {
    match self {
        ItemData::Login { .. } => ItemType::Login,
        ItemData::CryptoAddress { .. } => ItemType::CryptoAddress,
        ItemData::RecoveryPhrase { .. } => ItemType::RecoveryPhrase,
        ItemData::SecureNote { .. } => ItemType::SecureNote,
    }
}
```

- `match self` looks at which variant `self` is.
- `{ .. }` means "I do not care about the fields here".
- There is no `_ =>` fallback. If someone adds a fifth variant, this code stops compiling until they handle it. That is the point: a new kind of item cannot skip a security rule by accident.

In Kotlin you'd write: `when (this) { is Login -> ...; is CryptoAddress -> ... }` as an expression on a sealed type, which is also exhaustive.

### Newtypes

```rust
pub struct SecretText(Zeroizing<String>);
```

- A newtype is a struct with one unnamed field, written `(...)`.
- The inner field is private, so code outside the module cannot reach it. Only `expose()` hands out the text.
- `SecretText` and `Text` hold the same kind of data but are different types. You cannot pass a `SecretText` where a `Text` is expected, so a secret does not end up in a title field by a slip. The compiler stops the mix-up, but it does not stop code that calls `expose()` and logs the result. That part is review work.
- `Zeroizing<String>` overwrites the string's bytes when the value is dropped.

In Kotlin you'd write: `@JvmInline value class SecretText(private val value: String)`. Kotlin cannot wipe the string, but the type separation works the same way.

### `derive` versus hand-written `Debug`

```rust
impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText([REDACTED])")
    }
}
```

- `#[derive(Debug)]` would print every field, which for `SecretText` means the secret itself. So we write the impl by hand.
- `f.write_str` writes a fixed string. It never looks at `self.0`.
- `ItemData` does the same with a `match`: it prints `Login` or `SecureNote` and nothing else.
- `SecretText`, `GatedSecret` and `ItemData` have no `Clone`, so nobody can copy a secret without it being a visible decision. (`Text` holds no secret and does derive `Clone`.)
- None of the item, text or category types implement serde's `Serialize` or `Deserialize` either. Only crate-private wire types in `wire.rs` do, and they re-run every field rule when reading. Two `compile_fail` doctests in `lib.rs` prove that outside code cannot serialize an `Item` or deserialize a `GatedSecret`.

In Kotlin you'd write: a `data class` with an overridden `toString()` that returns `"SecretText([REDACTED])"`. Forgetting the override leaks, because a `data class` prints every field.

### `char` ranges in `matches!`

```rust
fn is_bidi(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}
```

- `'\u{202E}'` is a `char` written by its Unicode number. A `char` is one Unicode scalar value, not one byte.
- `'\u{202A}'..='\u{202E}'` is an inclusive range. It matches the five characters from 202A to 202E.
- `|` means "or". `matches!` gives back `true` if `c` fits any pattern.
- These characters flip the display direction of text. A title can look like `invoice` while holding something else, so display fields reject them.

In Kotlin you'd write: `c.code in 0x202A..0x202E || c.code in 0x2066..0x2069 || c == '\u061C'`. Kotlin `Char` is a UTF-16 unit, so characters outside the first 65 536 need `Int` code points. Rust `char` covers them all.

### Errors that name the field, never the value

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FieldError {
    #[error("{0:?} must not be empty")]
    Empty(Field),
    #[error("{0:?} is too long")]
    TooLong(Field),
    #[error("{0:?} contains a character that is not allowed")]
    ForbiddenChar(Field),
    #[error("too many URLs")]
    TooManyUrls,
    #[error("{0:?} is a reserved name")]
    Reserved(Field),
}
```

- `Field` is a plain enum such as `Title` or `Password`. The error holds that label and nothing else.
- Because the error is `Copy` and holds no text, it is safe to log, show in the UI or put in a test failure message.
- The `{0:?}` in the message prints the first field of the variant with `Debug`.

In Kotlin you'd write: a `sealed class FieldError` whose subclasses carry a `Field` enum. Not an exception built with `"Bad password: $value"`.

## Why this matters for security

Secrets leak through side doors: a debug print, a log line, an error message, a copy left in memory. The types here close those doors one by one. `Debug` is redacted, secrets have no `Clone` and no serde impls, memory is wiped on drop, and validation errors carry a label instead of the text that failed. A reviewer can check the whole policy by reading a few small impls.

## Try it

1. See the redaction test run.
   - Run: `cargo test -p holm-core --locked secret_text_debug_is_redacted`
   - Check: the `test result:` line says `ok. 1 passed`, followed by `filtered out` for the other tests.
   - Undo: nothing to undo, it only reads.
2. Prove `match` is exhaustive. Add a variant `Card {}` to the `ItemData` enum in `crates/holm-core/src/item.rs`.
   - Run: `cargo check -p holm-core --locked`
   - Check: the compiler reports `non-exhaustive patterns` and points at `item_type`.
   - Undo: `git checkout crates/holm-core/src/item.rs`
3. Break the secret rule on purpose. In `text.rs`, replace the hand-written `Debug` for `SecretText` with `#[derive(Debug)]` on the struct (and delete the impl).
   - Run: `cargo test -p holm-core --locked secret_text_debug_is_redacted`
   - Check: the test fails because the output shows the string instead of `[REDACTED]`.
   - Undo: `git checkout crates/holm-core/src/text.rs`

## Read next

- [Lesson 07: Modules and encapsulation](07-modules-and-encapsulation.md), for how a private field keeps a secret in one place.
- [Lesson 03: Errors and results](03-errors-and-results.md), for `Result` and the `?` operator.
- [The Rust book on enums and `match`](https://doc.rust-lang.org/book/ch06-00-enums.html)

Next lesson: none yet. Lesson 11 arrives with the next task.
