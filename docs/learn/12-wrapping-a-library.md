# Lesson 12: Wrapping a library

## What we built

Holm now checks how strong a master password is before a vault is made. `strength::check` takes a `&MasterPassword` and returns a `StrengthReport`: a score from 0 to 4, the length in characters, a yes or no, and zxcvbn's advice text. A password is accepted only with a score of at least 3 and at least 12 characters. All of the zxcvbn code sits behind this one function, so no other module sees the library.

## Rust ideas in this task

### A small API over a big dependency

```rust
pub struct StrengthVerdict { pub score: u8, pub chars: usize, pub acceptable: bool }
pub struct StrengthReport {
    pub verdict: StrengthVerdict,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}
pub fn check(password: &MasterPassword) -> StrengthReport
```

- The report uses only `u8`, `usize`, `String` and `Vec`. No zxcvbn type appears in it, so callers never need the zxcvbn crate, and Holm can swap the library later without touching them.
- `StrengthVerdict` is `Copy` because it is three small numbers. `StrengthReport` is not, because it owns strings.
- There is no `Serialize` or `Deserialize` on either type. Nothing here should be written to disk or sent anywhere by accident.
- Holm's two rules (`MIN_MASTER_SCORE` and `MIN_MASTER_CHARS`) live in our code as named constants, not inside the library call.

In Kotlin you'd write: an interface or a small data class that hides a third-party library, so the rest of the app imports only your type.

### `Option` and `Vec<String>` from a library

```rust
let (warning, suggestions) = match entropy.feedback() {
    Some(f) => (
        f.warning().map(|w| w.to_string()),
        f.suggestions().iter().map(ToString::to_string).collect(),
    ),
    None => (None, Vec::new()),
};
```

- `feedback()` returns `Option<&Feedback>`: there may be no advice at all (a strong password). `match` makes us handle both cases.
- `warning()` is also an `Option`. `.map(|w| w.to_string())` changes the inside of a `Some` and leaves `None` alone.
- `suggestions()` is a slice of enum values. `.iter().map(ToString::to_string).collect()` turns each into a `String` and gathers them into a `Vec<String>`. The type on the left decides what `collect` builds.
- `to_string()` copies the text. After that, the report owns its strings and no longer borrows from zxcvbn's result, so that result can be dropped.

In Kotlin you'd write: `feedback?.warning?.toString()` and `suggestions.map { it.toString() }`. Rust's `Option::map` is the `?.` call written out.

### Counting `char`s, and skipping the library for empty input

```rust
let chars = text.chars().count();
if chars == 0 {
    return refused();
}
```

- `str::len()` counts bytes. `chars().count()` counts Unicode scalar values. A password like `e` plus a combining accent is one visible letter but several `char`s, so Holm counts the NFC form, the same bytes the key derivation uses.
- `to_kdf_bytes()` gives those NFC bytes. `core::str::from_utf8` views them as `&str` without making a `String`, so we do not add a new un-wiped copy of the password.
- An empty password returns early with score 0. There is nothing to score, and we do not hand an empty string to the library.

In Kotlin you'd write: `text.codePointCount(0, text.length)`. Kotlin's `length` counts UTF-16 units, which has the same trap as Rust's `len()`.

### Seeing why a crate is in the tree: `cargo tree -i`

```text
cargo tree -p holm-core -e normal
cargo tree -i itertools
```

- `cargo tree` prints the dependency tree. `-i` (invert) starts from one crate and shows who needs it.
- Turning off zxcvbn's default features (`default-features = false` in the root `Cargo.toml`) did not remove much: it still needs `fancy-regex`, `regex`, `itertools`, `lazy_static` and `time`. One line of `Cargo.toml` brought in about 40 crates in `Cargo.lock`.
- Every one of them must pass `cargo deny` (licences, advisories, sources) and `cargo vet` (someone we trust vouches for it). Here the trust comes from crates.io publisher identity, with an expiry date, not from a review by us.

In Kotlin you'd write: `./gradlew dependencies` or `dependencyInsight --dependency itertools`.

### What a library may do with data you lend it

```rust
let entropy = zxcvbn::zxcvbn(text, USER_INPUTS);
// copy out the fixed advice text, then `entropy` is dropped at the end of `check`
```

- Lending `&str` means the library can read it, and it can also copy it. zxcvbn makes lowercase and look-alike variants as ordinary `String`s, and its result holds substrings of the password.
- Rust's borrow rules stop the library from keeping our reference after the call. They do not stop it from copying the bytes into its own memory. Freed memory is not zeroed, so a copy may sit in the heap until it is reused.
- What we can control: keep the result alive as short as possible, copy out only the fixed advice text (never the password), and write down the part we cannot control in `docs/CRYPTO.md` under "Known gaps".
- zxcvbn also scores only the first 100 characters, so the 12-character rule is the only check on anything longer.

In Kotlin you'd write: the same problem exists on the JVM. A `String` handed to a library can be copied and garbage collection never wipes it. Rust gives no magic fix here either, only the duty to say so.

## Why this matters for security

A strength check sees the secret that protects everything. So the rules are: it gets the password only as a borrow, it adds no un-wiped `String` of our own, its report holds only the library's fixed advice text (a test checks that weak passwords do not appear in the report, even in its `Debug` output), and the leftover copies inside the library are listed as a known gap instead of hidden. The dependency tree was checked by `cargo deny` and `cargo vet` with no self-written audits. A good score also does not make a short password safe: the length rule is separate, and Argon2id slows guessing but does not rescue a weak password.

## Try it

1. Run the strength tests.
   - Run: `cargo test -p holm-core --locked strength`
   - Check: the `test result:` line says `ok.` with 0 failed.
   - Undo: nothing to undo, it only reads.
2. Break the length rule. In `crates/holm-core/src/strength.rs`, change `chars >= MIN_MASTER_CHARS` to `true`.
   - Run: `cargo test -p holm-core --locked eleven_strong_chars_refused_for_length`
   - Check: the test fails, because an 11-character password is now accepted.
   - Undo: `git checkout crates/holm-core/src/strength.rs`
3. See who needs a crate.
   - Run: `cargo tree -i fancy-regex`
   - Check: the output ends at `zxcvbn` and then `holm-core`.
   - Undo: nothing to undo, it only reads.

## Read next

- [The Rust book, ch09-02: recoverable errors with `Result`](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html)
- [std::option::Option](https://doc.rust-lang.org/std/option/enum.Option.html)
- [std::iter::Iterator::collect](https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.collect)
- [The Cargo book: cargo tree](https://doc.rust-lang.org/cargo/commands/cargo-tree.html)
- [zxcvbn crate documentation](https://docs.rs/zxcvbn)

Next lesson: none yet. Lesson 13 arrives with the next task.
