# Lesson 08: Property tests and fuzzing

## What we built

`crates/holm-core/tests/format_props.rs` holds property tests for the header parser and the
padding. `fuzz/` holds three cargo-fuzz targets (`parse_header`, `parse_header_structured`,
`unpad`) and `fuzz/README.md` says how to run them. `scripts/ci-local.sh` runs a short
fuzz pass as a gate. The goal: the code that reads untrusted bytes returns an error for bad
input and never panics.

## Rust ideas in this task

### 1. `panic!` versus `Result`

From `crates/holm-core/src/padding.rs`:

```rust
let (body, tail) = rest.split_at_checked(len).ok_or(VaultError::BadPadding)?;
```

Line by line:
- `rest.split_at(len)` would panic if `len` is bigger than `rest`. `split_at_checked`
  returns an `Option` instead: `Some((head, tail))` or `None`.
- `.ok_or(VaultError::BadPadding)` turns `None` into `Err(BadPadding)`.
- `?` returns that error to the caller. Here `len` came from four bytes of the file, so an
  attacker chose it.

A panic is for "this can only happen if our own code is wrong". A `Result` is for "the
outside world gave us something bad". File contents always belong to the second kind.

In Kotlin you'd write: `rest.copyOfRange(0, len)` throws `IndexOutOfBoundsException`, and
a `try`/`catch` somewhere may or may not catch it. In Rust, a panic unwinds (or aborts)
the whole thread unless someone uses `catch_unwind`, and the compiler does not force you
to handle it. A `Result` must be handled, or the compiler warns.
([To panic! or not to panic!](https://doc.rust-lang.org/book/ch09-03-to-panic-or-not-to-panic.html))

### 2. A property test with `proptest!`

From `format_props.rs`:

```rust
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn parse_never_panics_on_random(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        check_parse(&bytes)?;
    }
}
```

Line by line:
- `proptest! { ... }` is a macro. It turns each `fn` inside into a normal `#[test]` that
  runs many times.
- `with_cases(256)` sets how many random inputs one run tries.
- `bytes in prop::collection::vec(any::<u8>(), 0..400)` is a strategy: a recipe for
  generating a `Vec<u8>` of 0 to 399 random bytes. `any::<u8>()` is the recipe for one
  byte.
- `check_parse(&bytes)?` returns `Result<(), TestCaseError>`. A panic inside it, or an
  `Err`, fails the case. Then proptest shrinks the input: it tries smaller versions until
  it finds a minimal failing one, and prints it.

Instead of "for this input, expect that output", a property says "for every input, this is
true". Here: parse never panics, and if parse accepts the header, encoding it again gives
back the same 164 bytes.

In Kotlin you'd write: Kotest `forAll(Arb.byteArray(Arb.int(0..399), Arb.byte())) { ... }`.
Same idea, and Kotest also shrinks failures.
([proptest book](https://proptest-rs.github.io/proptest/intro.html))

### 3. Building valid inputs with `prop_flat_map`

```rust
(3u32..=16)
    .prop_flat_map(|iterations| {
        let max_m = u64::from(MAX_M_KIB).min(MAX_WORK / u64::from(iterations));
        let max_m = u32::try_from(max_m).expect("capped by MAX_M_KIB");
        (Just(iterations), 65_536u32..=max_m)
    })
```

Line by line:
- `(3u32..=16)` is a strategy that picks an iteration count from 3 to 16.
- `prop_flat_map` takes the value that was picked and returns a second strategy that may
  depend on it. The header limits memory times iterations to `MAX_WORK`, so the allowed
  memory range depends on the iteration count that was just chosen.
- `Just(iterations)` is a strategy that always gives the same value, so the pair carries
  both numbers forward.
- `u32::try_from(max_m).expect(...)` is allowed in test code: a failure here means the
  test itself is wrong, not the input.

In Kotlin you'd write: `Arb.int(3..16).flatMap { it -> Arb.int(65536..maxFor(it)).map { m
-> it to m } }`. Same shape.
([Strategies](https://proptest-rs.github.io/proptest/proptest/tutorial/strategy-basics.html))

### 4. Structure-aware fuzzing with `Arbitrary`

From `fuzz/fuzz_targets/parse_header_structured.rs`:

```rust
#[derive(Arbitrary, Debug)]
enum Edit {
    Xor { offset: u16, value: u8 },
    Truncate { len: u16 },
    Extend { extra: Vec<u8> },
}
```

and, further down:

```rust
let mut bytes = header.encode().to_vec();
bytes.extend_from_slice(&body);
// ... apply up to 4 edits to `bytes` ...
if let Ok((parsed, _body)) = Header::parse(&bytes) {
    assert_eq!(&parsed.encode()[..], &bytes[..HEADER_LEN]);
}
```

Line by line:
- `#[derive(Arbitrary)]` generates code that turns the fuzzer's raw bytes into an `Edit`
  value. The fuzzer still mutates plain bytes, but those bytes now decode into structured
  input.
- The target first builds a valid file with `encode`, so it starts past the magic bytes,
  the version and the length fields.
- The edits then damage that valid file in a few places. Most inputs are "almost valid",
  which is where parser bugs hide: a length that is off by one, a field just over its limit.
- The `assert_eq!` is the property. If the parser accepts bytes, they must be exactly what
  `encode` would write for the parsed header. Anything else means the parser accepted a
  second spelling of the same header.

Random bytes are rejected at the first check, the 8-byte magic, almost every time, so the
code behind it barely runs. The raw `parse_header` target is seeded with one valid file
(`fuzz/seeds/parse_header/valid_floor`) for the same reason.

In Kotlin you'd write: a Jazzer `FuzzedDataProvider` that you read fields from by hand.
`#[derive(Arbitrary)]` writes that code for you.
([Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz.html),
[`arbitrary`](https://docs.rs/arbitrary))

### 5. Reading a crash and turning it into a test

If a target crashes, libFuzzer prints a panic message and writes the input to
`fuzz/artifacts/<target>/crash-<hash>`. The steps, as in `fuzz/README.md`:

```sh
cargo +nightly fuzz run parse_header fuzz/artifacts/parse_header/crash-<hash>
cargo +nightly fuzz tmin parse_header fuzz/artifacts/parse_header/crash-<hash>
```

Line by line:
- The first command runs the target on that one file, so you see the panic message and the
  file and line again. Read the line number first: it names the check that was missing.
- `tmin` shrinks the input while it still crashes. A small input is easier to read.
- Then copy the small input to `fuzz/seeds/<target>/regression_<name>`, write a unit test
  that feeds the same bytes to the function and expects `Err(..)`, watch it fail, fix the
  code, and watch it pass.

The unit test is what keeps the bug fixed. The fuzzer's corpus is local and git-ignored.

In Kotlin you'd write: the same flow with Jazzer, where a crash file becomes a JUnit test
with the bytes pasted in.

## Why this matters for security

A parser reads bytes an attacker controls. A panic there is a bug an attacker can trigger
on purpose: at best the app crashes when a vault is opened, at worst a lock is poisoned or
a secret is left unwiped because `Drop` never ran on an aborted path. Property tests and
fuzzing find the inputs a human did not think of, but they only show that those inputs
were tried, not that none exist; a clean run is evidence, not proof.

## Try it

Run each one from the repo root. Undo after each: `git checkout crates/ && rm -f
crates/holm-core/tests/format_props.proptest-regressions`

1. Add this to the end of `crates/holm-core/tests/format_props.rs`, then run
   `cargo test -p holm-core --test format_props first_four`:

   ```rust
   fn first_four(b: &[u8]) -> [u8; 4] {
       b[..4].try_into().unwrap()
   }

   proptest! {
       #[test]
       fn first_four_never_panics(b in prop::collection::vec(any::<u8>(), 0..8)) {
           let _ = first_four(&b);
       }
   }
   ```

   Check: the test fails and proptest reports `minimal failing input: b = []`, with a
   panic message about the range end index 4. Shrinking got from a random vector to the
   empty one.
2. Replace `first_four` with a version that returns a `Result`, and update the test. Run
   the same command.

   ```rust
   fn first_four(b: &[u8]) -> Result<[u8; 4], ()> {
       b.first_chunk::<4>().copied().ok_or(())
   }
   ```

   Check: it passes. The empty and short inputs now give `Err(())` instead of a panic, and
   `let _ =` ignores the result in the test.
3. Add a test that feeds the committed seed file to the parser, then run
   `cargo test -p holm-core --test format_props seed_file_parses`:

   ```rust
   #[test]
   fn seed_file_parses() {
       let seed = include_bytes!("../../../fuzz/seeds/parse_header/valid_floor");
       assert!(Header::parse(seed).is_ok());
   }
   ```

   Check: it passes. This is the shape of a crash regression test: bytes in, expected
   result out. For a real crash you would paste the `tmin` output and assert `is_err()`.

## Read next

- *The Rust Programming Language* [chapter 9.3, To `panic!` or Not to `panic!`](https://doc.rust-lang.org/book/ch09-03-to-panic-or-not-to-panic.html)
- [The Rust Fuzz Book, `cargo fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [The proptest book](https://proptest-rs.github.io/proptest/intro.html)
