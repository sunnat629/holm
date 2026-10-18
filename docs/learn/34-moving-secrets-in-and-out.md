# Lesson 34: Moving secrets in and out

## Why this matters

Every write command moves a secret from one place to another: from the terminal into an item,
from an item onto the clipboard, from the vault into an export file. Each move is a chance to
leave a stray copy in memory that nobody wipes, or a value on the clipboard that stays there
all day. Rust lets us say exactly when a value is moved, copied or dropped, so we can make each
move leave nothing behind.

## What we built

`holm add`, `edit`, `rm`, `passwd`, `import` and `export` are in `crates/holm-cli/src/commands/`
(`write.rs` and `transfer.rs`). `holm get ID --copy FIELD` and `holm gen --copy` are in
`copy.rs`: they put one value on the macOS pasteboard, marked concealed so clipboard managers
skip it, wait for the vault's clear time or Enter, then clear the clipboard only if it still
holds Holm's value. The clipboard itself is `holm-platform`'s `ConcealedClipboard` (feature
`clipboard`), and `Env.clip` is a factory, so the tests swap in a fake one.

## Rust ideas in this task

### 1. `std::mem::take`: move the bytes, leave an empty buffer

A password typed at the prompt arrives as `Zeroizing<String>`. The item wants a `SecretText`,
which takes a plain `String` by value and wipes it on drop. Copying would leave two heaps holding the
password. `mem::take` moves the `String` out and puts an empty one in its place:

```rust
fn secret_of(mut typed: Zeroizing<String>) -> SecretText {
    SecretText::new(mem::take(&mut *typed))
}
```

`&mut *typed` reaches through `Zeroizing`'s `DerefMut` to the `String` inside. `take` swaps in
`String::new()` (no heap) and hands back the original, heap and all, so the bytes never move.
When `typed` drops at the end of the function, it wipes an empty string, and `SecretText` now
owns the only copy.

In Kotlin you'd write `val chars = typed.copyOf(); typed.fill('\u0000')`: copy, then wipe the
old array by hand. Kotlin can't hand over ownership, so there is always a moment with two copies.

### 2. `to_owned()` straight into a wiping type

Sometimes a copy can't be avoided. `holm edit` keeps the stored password when you don't change
it, and the core wants a new `SecretText` for the new item. The rule: the copy goes straight
into a wiping type, in the same expression, so no plain `String` ever has a name.

```rust
fn keep(s: &SecretText) -> SecretText {
    SecretText::new(s.expose().to_owned())
}
```

`--copy` does the same with `Zeroizing`:

```rust
(CopyField::Password, ItemData::Login { password, .. }) => {
    Zeroizing::new(password.expose().to_owned())
}
```

`to_owned()` allocates exactly the length of the `&str`, so there is no growing `String` that
reallocates and leaves old copies behind (lesson 32). The temporary `String` is moved into the
wrapper; it is never bound to a variable that could be logged or cloned.

The clipboard read-back for the "still Holm's value?" check works the same way: arboard returns
a `String`, and `.map(Zeroizing::new)` moves it into a wiping buffer before the compare.

In Kotlin you'd write `SecretText(password.expose().copyOf())` and trust the garbage collector,
which may have copied the old array during a compaction already.

### 3. `Box<dyn Fn>` factories in `Env`

The real clipboard can't run in CI, and a test must not replace the developer's clipboard.
So `Env` doesn't hold a clipboard; it holds a function that opens one:

```rust
pub struct Env {
    pub clip: Box<dyn Fn() -> Result<Box<dyn Clip>, ClipboardError>>,
    // ...
}
```

`main.rs` passes the real one:

```rust
clip: Box::new(|| Ok(Box::new(ConcealedClipboard::open()?) as Box<dyn Clip>)),
```

and the tests pass a closure that captures a shared `Rc<RefCell<ClipState>>`, so the test can
look at what was "copied" after the run:

```rust
clip: Box::new(move || Ok(Box::new(FakeClip(Rc::clone(&state))) as Box<dyn Clip>)),
```

Why a factory and not a `Box<dyn Clip>`? `holm list` never opens the clipboard, so it never
loads AppKit's pasteboard. `--copy` opens it first, before any prompt, so a system without a
clipboard says so at once instead of after the master password. The `as Box<dyn Clip>` cast
tells the compiler which trait object to build; without it the closure's return type is
`Box<ConcealedClipboard>`, which doesn't match.

In Kotlin you'd write `val clip: () -> Clip = { ConcealedClipboard.open() }`, a factory lambda,
and pass `{ FakeClip(state) }` in tests.

### 4. `Instant` deadlines for the wait

`copy_and_wait` computes one deadline and hands it to the terminal:

```rust
clip.set(&value).map_err(|_| CliError::CopyFailed)?;
let until = Instant::now() + Duration::from_secs(u64::from(secs));
let said = writeln!(err, "Copied. Holm clears the clipboard in {secs} seconds. ...");
let waited = term.wait_for_key(until);
let unchanged = clip.holds(&value);
if unchanged {
    clip.clear();
    if clip.holds(&value) {
        return Err(CliError::ClearFailed);
    }
}
drop(value);
said?;
waited?;
```

Three things to see:

- `Instant` is monotonic. If the wall clock jumps (NTP, a time-zone change), the wait does not
  get longer or shorter. `SystemTime` would.
- `wait_for_key` polls the terminal every 0.1 s and compares against `until`. One deadline,
  computed once, means a slow write or a key press doesn't reset the clock.
- `said` and `waited` are kept as `Result`s and only checked with `?` *after* the clear. If the
  message fails to print or the terminal goes away, the clipboard is still cleared first. A
  `?` straight after `writeln!` would have returned with the password still on the clipboard.

`drop(value)` makes the wipe explicit: the `Zeroizing<String>` is gone before anything else is
printed.

In Kotlin you'd write `val until = TimeSource.Monotonic.markNow() + secs.seconds` and check
`until.hasPassedNow()`; with `java.time` you'd use `System.nanoTime()`, never
`currentTimeMillis()`.

## Exercises

1. Add a unit test in `write.rs` for `secret_of`: build a `Zeroizing<String>` from
   `"EXAMPLE-pw"`, pass it in, and check that the `SecretText` exposes `"EXAMPLE-pw"`. (You
   can't look at the moved-from buffer after the call; explain in a comment why that is the
   point.) Check: `cargo test -p holm-cli --locked --lib`
2. Give `ClipState` in `tests/common/mod.rs` a `refuse` flag that makes `FakeClip::set` return
   `Err(ClipboardError::Refused)`, then write a test in `tests/write_commands.rs` that sets it. Check that the
   run exits 1 with `CliError::CopyFailed`'s text, that nothing was printed to `out`, and that
   no "Clipboard cleared." line appears. Check: `cargo test -p holm-cli --locked --test
   write_commands copy_`
3. `gen --copy` always waits `CLIPBOARD_DEFAULT_SECS`. Give `GenArgs` a `--clear-after SECS`
   option, capped at 300. Make `FakeTerminal::wait_for_key` record the `until` it gets, and test
   that it is about that far in the future. Check: `cargo test -p holm-cli --locked`

## Read next

- [std::mem::take](https://doc.rust-lang.org/std/mem/fn.take.html)
- [std::time::Instant](https://doc.rust-lang.org/std/time/struct.Instant.html)
- [Lesson 33: A CLI without a framework](33-a-cli-without-a-framework.md)
