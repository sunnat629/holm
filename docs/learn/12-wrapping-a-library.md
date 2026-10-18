# Lesson 12: Owning the check instead of wrapping a library

## What we built

Holm checks how strong a new master password is before it makes a vault. `strength::check` takes a `&MasterPassword` and returns a `StrengthReport`: a score from 0 to 4, the length in characters, a yes or no, and fixed advice text. A password is accepted only with a score of at least 3 (an estimated 10^8 guesses or more) and at least 12 characters.

The first version wrapped the `zxcvbn` crate. Review found that it added 17 crates nobody had reviewed to `holm-core`'s production tree, read the system clock, and copied the password into many ordinary `String`s that are never wiped. So the check is now Holm's own code: a port of zxcvbn's model, about 1,800 lines with tests, in `crates/holm-core/src/strength/`. The `zxcvbn` crate stays only as a dev-dependency, where a test uses it as an oracle.

The check has three steps:

1. Find guessable pieces: listed words (also capitalised, reversed or in l33t), `holm`, keyboard walks, repeats, sequences, years and dates.
2. Find the cheapest way to build the whole password from those pieces, pricing gaps as random characters.
3. Turn the guess count into a score.

## Rust ideas in this task

### Data in the binary: `include_str!` plus a pinned hash

```rust
const RAW: &str = include_str!("frequency_lists.coffee");

pub(crate) fn entries() -> &'static [Entry] {
    static LIST: OnceLock<Vec<Entry>> = OnceLock::new();
    LIST.get_or_init(build)
}
```

- `include_str!` reads the file at compile time and puts its text in the binary as a `&'static str`. Nothing is read from disk at run time.
- The file is a byte-exact copy of zxcvbn's MIT word lists. `NOTICE` records where it came from, and `scripts/ci-local.sh` checks its SHA-256, so a changed byte stops the merge.
- `OnceLock` builds the parsed, sorted list the first time it is needed, and every later call gets the same `&'static` slice. Each `Entry` holds a `&'static str` slice of `RAW`, so parsing copies no words.

In Kotlin you'd write: a resource file loaded with `javaClass.getResource(...)` inside a `by lazy { ... }` property. Rust checks it at compile time: a missing file is a build error, not a runtime `null`.

### Scratch buffers that wipe: `Zeroizing<Vec<T>>`

```rust
pub(crate) fn push_wiped<T: DefaultIsZeroes>(v: &mut Zeroizing<Vec<T>>, x: T) {
    if v.len() == v.capacity() {
        let mut bigger = Zeroizing::new(Vec::with_capacity(v.capacity().saturating_mul(2).max(16)));
        bigger.extend_from_slice(v);
        *v = bigger;
    }
    v.push(x);
}
```

- `Zeroizing<Vec<T>>` overwrites its whole allocation with zeros when it drops. The password's characters, the lower-cased copy, every match and the cheapest-split table all live in one of these.
- A plain `push` on a full `Vec` moves the data to a bigger allocation and frees the old one *without* wiping it. `push_wiped` does the move itself: it copies into a new `Zeroizing` vector, and the assignment `*v = bigger` drops the old one, which wipes it.
- `DefaultIsZeroes` is a marker trait. It says "a `Copy` type whose `Default` value is all zeros", which lets `zeroize` wipe any such type, including our own `Match` struct.

In Kotlin you'd write: a `CharArray` that you fill with `'\u0000'` in a `finally` block. Rust runs the wipe in `Drop` instead, so an early `return` or a panic cannot skip it.

### Working on `&[char]`, not `&str`

```rust
pub(crate) struct Text<'a> {
    pub(crate) chars: &'a [char],
    pub(crate) lower: &'a [char],
}
```

- A `&str` is UTF-8 bytes, so you cannot jump to "character 7" without walking from the start. The matchers compare characters by position all the time, so `check` copies the NFC text into a `[char]` buffer once. Then `chars[i]` is the i-th Unicode scalar value.
- `lower` is a second slice of the same length with ASCII letters lower-cased. Index `i` means the same position in both, so a word found in `lower` can still have its capitals checked in `chars`.
- `Text` is `Copy`: it is two borrowed slices, so passing it around copies two pointers and two lengths, never the password.

In Kotlin you'd write: `text.codePoints().toArray()`. Kotlin's `String.length` and `get(i)` count UTF-16 units, so an emoji takes two slots. Rust's `str::len()` has the same trap, in bytes.

### The cheapest split: a table indexed by position

```rust
fn cell(end: usize, pieces: usize, gap: bool) -> usize {
    (end * MAX_PIECES + (pieces - 1)) * 2 + usize::from(gap)
}
```

- For every end position, piece count (1 to 4) and "ends in a random gap or not", the table keeps the cheapest split found so far. One flat `Vec` with an index function avoids a `Vec<Vec<Vec<_>>>`, which would make many small allocations, each needing its own wipe.
- Each match covering positions `i..=j` extends the best splits that end at `i - 1`. When every position is done, the answer is the cheapest cell at the last position. This is dynamic programming: each cell is computed once from earlier cells.
- `usize::from(bool)` turns `false` into 0 and `true` into 1, with no `as` cast.
- The limits (4 pieces, gaps of at most 10 characters) keep the work linear in the password's length. The module docs explain why they cannot change the score: more pieces, or a longer gap, cost over 10^10 on their own.

In Kotlin you'd write: `Array(n * 4 * 2) { Cell() }` and the same index arithmetic. The idea is the same in both languages. Rust adds the wipe on drop and bounds-checked indexing.

### A dev-only oracle test

```toml
[dev-dependencies]
# Test oracle only: tests/strength_oracle.rs checks Holm's own estimator against it.
zxcvbn.workspace = true
```

- A `[dev-dependencies]` crate is built only for tests, examples and benchmarks. It is never linked into the library or into any binary that uses it.
- `tests/strength_oracle.rs` builds about 12,000 weak candidates from fixed word lists, suffixes and variants. It asserts that Holm refuses every one that zxcvbn scores below 3, and that Holm's score is never above zxcvbn's. A second test checks that strong passphrases and random strings are still accepted, so the check cannot pass by refusing everything.
- Because zxcvbn is dev-only, `cargo vet` needs its tree to be only `safe-to-run` (fine to build and test on our machines), not `safe-to-deploy`.

In Kotlin you'd write: `testImplementation("...")` in Gradle. Same idea: the oracle library stays on the test classpath.

## Why this matters for security

The strength check sees the one secret that protects every other secret, just before Holm makes the vault. Owning the code lets us promise what the library could not:

- Every heap buffer derived from the password is wiped.
- Nothing reads the clock, so the same password always gets the same answer.
- The whole password is judged. zxcvbn scored only the first 100 characters.
- The feedback is fixed text from a table, and a test checks that report text comes from nowhere else.

The cost is that our estimator could have bugs. The oracle test bounds that risk on a fixed corpus but does not prove the code correct. `docs/CRYPTO.md` lists the remaining limits: English-centric lists, and two work bounds that a crafted, very long input could slip past.

## Try it

1. Run the unit tests and the oracle.
   - Run: `cargo test -p holm-core --locked --lib strength`, then `cargo test -p holm-core --locked --test strength_oracle`
   - Check: both `test result:` lines say `ok.` with 0 failed; the second shows `2 passed`.
   - Undo: nothing to undo, it only reads.
2. Tamper with the word list and watch the hash gate catch it.
   - Run: `printf 'x' >> crates/holm-core/src/strength/frequency_lists.coffee && grep -o '664d[0-9a-f]*  crates/holm-core/src/strength/frequency_lists.coffee' scripts/ci-local.sh | shasum -a 256 -c -`
   - Check: it prints `crates/holm-core/src/strength/frequency_lists.coffee: FAILED` and exits with an error.
   - Undo: `git checkout crates/holm-core/src/strength/frequency_lists.coffee`
3. Confirm zxcvbn never reaches production.
   - Run: `cargo tree -e normal -p holm-core --locked | grep -c zxcvbn`, then `cargo tree -e dev -p holm-core --locked -i zxcvbn`
   - Check: the first prints `0`. The second shows `zxcvbn` under `[dev-dependencies]` of `holm-core` and nothing else.
   - Undo: nothing to undo, it only reads.

## Read next

- [The Rust book, ch08-02: storing UTF-8 text with strings](https://doc.rust-lang.org/book/ch08-02-strings.html)
- [std::sync::OnceLock](https://doc.rust-lang.org/std/sync/struct.OnceLock.html)
- [zeroize::Zeroizing](https://docs.rs/zeroize/latest/zeroize/struct.Zeroizing.html)

Next lesson: none yet. Lesson 13 arrives with the next task.
