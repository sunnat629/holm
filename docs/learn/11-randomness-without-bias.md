# Lesson 11: Randomness without bias

## What we built

Holm can now make passwords, passphrases and usernames. Every random choice comes from the operating system's random number generator, and every choice is unbiased: no character or word is more likely than another. Passwords and passphrases come back as `SecretText`, which wipes its memory when dropped. Passphrases use the EFF large wordlist of 7 776 words, built into the program.

## Rust ideas in this task

### Why `% n` is biased, and rejection is not

```rust
pub(crate) fn uniform_below(rng: &mut dyn RandomSource, n: NonZeroU32) -> Result<u32, GeneratorError> {
    let n = u64::from(n.get());
    let bound = (1u64 << 32) / n * n;
    loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b).map_err(|_| GeneratorError::Rng)?;
        let x = u64::from(u32::from_le_bytes(b));
        if x < bound {
            return u32::try_from(x % n).map_err(|_| GeneratorError::Rng);
        }
    }
}
```

- A random `u32` has 2^32 possible values. If `n` does not divide 2^32 evenly, then `x % n` gives the small remainders one extra chance each. Example with `n = 3`: 2^32 = 3 x 1 431 655 765 + 1, so remainder 0 comes up once more than 1 and 2.
- The bias is tiny for small `n`, but a password generator should have none.
- `bound` is the largest multiple of `n` that fits in 2^32. Values at or above `bound` are thrown away and we draw again. Below `bound`, every remainder has exactly the same number of values.
- `loop` runs until a value is accepted. The chance of a reject is below `n / 2^32`, so it almost never loops twice.
- We use `u64` for the math because 2^32 itself does not fit in a `u32`.

In Kotlin you'd write: a `while (true)` loop with `Random.nextInt()`. The same trap exists there: `nextInt() % n` is biased, and `nextInt(n)` already does the rejection for you.

### `NonZeroU32`

```rust
use core::num::NonZeroU32;
let n = NonZeroU32::new(3).unwrap();
```

- `x % 0` would panic. A `NonZeroU32` is a `u32` that the type system says is not zero, so `uniform_below` cannot be called with a zero.
- `NonZeroU32::new(v)` returns `Option`: `None` for zero. The check happens once, where the value is made.
- `n.get()` turns it back into a plain `u32`.

In Kotlin you'd write: a `require(n > 0)` at the top of the function. Rust moves that check into the type.

### `dyn Trait` as a test seam

```rust
pub(crate) trait RandomSource {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError>;
}
pub(crate) struct OsRandom;
```

- A trait is a list of methods a type promises to have. `&mut dyn RandomSource` means "any value that has `fill`", chosen when the program runs.
- Real code passes `OsRandom`, which calls the OS. Tests pass `SeqSource`, which returns chosen numbers, so a test can prove the biased tail is rejected.
- `pub(crate)` keeps the seam inside the crate. Outside code cannot swap in a weak random source.

In Kotlin you'd write: an `interface RandomSource` with a fake in tests. Same idea; Rust marks it `pub(crate)` where Kotlin would say `internal`.

### `include_str!` and `OnceLock`

```rust
pub(crate) fn wordlist() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| {
        include_str!("eff_large_wordlist.txt")
            .lines()
            .filter_map(|l| l.split_once('\t').map(|(_, w)| w))
            .collect()
    })
}
```

- `include_str!` copies the file into the program when it is built, as a `&'static str`. There is no file to read at run time and nothing to tamper with on disk.
- `OnceLock` holds a value that is set once. `get_or_init` runs the closure the first time and returns the same value after that, even from several threads.
- Each line is `11111<TAB>abacus`. `split_once('\t')` cuts it in two and we keep the word. The words point into the built-in text, so no copies are made.
- Four words contain a hyphen (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`). A test pins this, so a `-` separator cannot be assumed to split words cleanly.

In Kotlin you'd write: `val words by lazy { resource("words.txt").lines() }`. `lazy` plays the role of `OnceLock`.

### `f64::log2` for entropy

```rust
let bits = f64::from(self.length) * pool.log2();
```

- Entropy in bits is how many yes/no guesses an attacker needs: a pool of 94 characters gives `log2(94)`, about 6.55 bits per character.
- `f64::from(u16)` converts without loss. Turning a `usize` into `f64` needs `as`, which clippy flags, so we allow it on that one line.
- A spec below 64 bits is refused.

In Kotlin you'd write: `kotlin.math.log2(94.0)`.

## Why this matters for security

A biased generator gives an attacker a shortcut, and the bias never shows up in normal use. Rejection sampling removes it, a test feeds the exact worst value (`u32::MAX`) to prove it, and a chi-square test checks that 200 000 characters spread evenly. The OS random source is the only real source, the test seam cannot be reached from outside the crate, and results live in `SecretText`.

## Try it

1. Run the generator tests.
   - Run: `cargo test -p holm-core --locked generator`
   - Check: the `test result:` line says `ok.` with 0 failed.
   - Undo: nothing to undo, it only reads.
2. Make the bias come back. In `uniform_below` in `crates/holm-core/src/generator.rs`, change `if x < bound {` to `if true {`.
   - Run: `cargo test -p holm-core --locked uniform_below_rejects_biased_tail`
   - Check: the test fails, because `u32::MAX % 3` is accepted instead of rejected.
   - Undo: `git checkout crates/holm-core/src/generator.rs`
3. See the wordlist check catch a change. Delete one line from `crates/holm-core/src/eff_large_wordlist.txt`.
   - Run: `cargo test -p holm-core --locked wordlist_integrity`
   - Check: the test fails on the 7 776 count.
   - Undo: `git checkout crates/holm-core/src/eff_large_wordlist.txt`

## Read next

- [The Rust book, ch10-02: traits](https://doc.rust-lang.org/book/ch10-02-traits.html), for `trait` and `dyn`.
- [std::sync::OnceLock](https://doc.rust-lang.org/std/sync/struct.OnceLock.html)
- [std::num::NonZeroU32](https://doc.rust-lang.org/std/num/type.NonZeroU32.html)

Next lesson: none yet. Lesson 12 arrives with the next task.
