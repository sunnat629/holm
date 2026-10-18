# Lesson 35: A read-eval loop with a deadline

## Why this matters

A one-shot command is easy to make safe: it opens the vault, does one thing, and the process
ends. A shell is different. It keeps the vault open while you think, so it must notice when you
walk away, lock on its own, clear the clipboard on time, and never let one bad line end the
session or leave a secret behind. All of that comes down to one loop that reads a line, does
it, and waits for the next line, but never waits forever.

## What we built

`holm shell` is in `crates/holm-cli/src/shell.rs`. It takes the vault folder's lock once, keeps
one `Session` for its whole life, and runs a loop: show `holm> ` (or `holm (locked)> `), read a
line with a deadline, lock if the idle time has passed, clear the clipboard if its time has
come, then split the line into words and run the command. The one-shot handlers were split so
the shell can call their bodies on its open session (`add_to`, `edit_in`, `rm_in`,
`passwd_in`, `import_into`, `export_to`), and `vault::unlock_once` is one try at the master
password, used by both.

## Rust ideas in this task

### 1. `loop` and `match` on an outcome

The shell's heart is a `loop` with no condition. Each turn produces an outcome, and a `match`
decides what happens next:

```rust
loop {
    let read = term.line(prompt, MAX_SHELL_LINE_BYTES, self.deadline());
    self.on_wake(err)?;
    let line = match read {
        Ok(None) => continue,                // the deadline passed
        Ok(Some(line)) => line,              // a typed line
        Err(TtyError::Cancelled) => { /* Ctrl-D: lock and leave */ }
        Err(e @ (TtyError::TooLong | TtyError::NotUtf8)) => { /* say so */ continue; }
        Err(e) => return Err(e.into()),      // the terminal is gone
    };
    match self.line(&line, term, out, err)? {
        Flow::Continue => {}
        Flow::Exit => return Ok(()),
    }
}
```

Three things to see:

- `match` must cover every case, so adding a new `TtyError` variant later is a compile error
  here until someone decides what the shell does with it.
- `e @ (A | B)` binds the matched value to `e` while matching either pattern.
- `Flow` is a two-variant enum instead of a `bool`. `Flow::Exit` reads better than `true`, and
  a third outcome can be added without changing every caller's meaning.

Notice too that `on_wake` runs *before* the line is looked at. If you typed a line after the
idle time had passed (say the Mac slept), the vault locks first and the line runs against a
locked vault.

In Kotlin you'd write `while (true) { when (val r = read()) { is Line -> …; is Timeout ->
continue; … } }`. A `sealed class` plays the role of the enum, and `when` is exhaustive over
it in the same way.

### 2. `Option<Instant>` and the earlier of two times

A prompt may have to return on its own for two reasons: the auto-lock time, and a pending
clipboard clear. Either may be missing: a locked vault has no auto-lock, and there may be
nothing on the clipboard. So each is an `Option`, and the deadline is the earlier of the ones
that exist:

```rust
let idle = self.session.is_unlocked().then(|| self.last_active + auto_lock);
let clear = self.pending.as_ref().map(|p| p.at);
let target = idle.into_iter().chain(clear).min()?;
```

`bool::then` turns a condition into `Some(value)` or `None`. An `Option` is an iterator of zero
or one item, so `chain` joins the two and `min` picks the earlier. If both are `None`, `min`
returns `None` and `?` returns `None` from the function: the prompt waits with no deadline.

The times are `Duration`s on the shell's `Clock` (so tests can move time by hand), turned into
a real `Instant` only at the last moment:

```rust
let wait = target.saturating_sub(self.clock.monotonic()).max(MIN_WAIT);
Some(Instant::now() + wait)
```

`saturating_sub` gives zero instead of panicking when the target is already past, and
`max(MIN_WAIT)` keeps a deadline that is a hair early from making the loop spin.

The deadline is only a hint to wake up. The decision to lock is the session's own
`idle_expired()`, which checks the monotonic clock and a forward jump of the wall clock. Two
clocks never have to agree for the shell to be safe.

In Kotlin you'd write `listOfNotNull(idle, clear).minOrNull()`, or `minOf(a, b)` once both are
known to be there.

### 3. The tokenizer as a small state machine

`tokenize` turns `add note --title "My note"` into four words. It walks the characters once and
remembers one thing: where it is.

```rust
enum Mode { Gap, Word, Single, Double }
```

Each character, together with the mode, decides what happens:

```rust
match (mode, c) {
    (Mode::Single, '\'') | (Mode::Double, '"') => mode = Mode::Word,
    (Mode::Double, '\\') => escaped = true,
    (Mode::Single | Mode::Double, c) => all.push(c),
    (Mode::Gap, c) if c.is_whitespace() => {}
    (Mode::Word, c) if c.is_whitespace() => { spans.push((start, all.len())); mode = Mode::Gap; }
    (Mode::Gap | Mode::Word, c) => { /* start a word, open a quote, or push c */ }
}
```

Matching on a tuple `(mode, c)` puts the whole transition table in one place, and the compiler
checks that every pair is covered. At the end, the mode tells you if the line was finished: a
line that ends in `Single` or `Double` has an open quote and is refused.

The words hold what you typed, so they are built carefully. Every character goes into one
`Zeroizing<String>` made with `with_capacity(line.len())`, which never grows and so never leaves
an old copy behind. Each word is then copied out at its exact size into its own wiping buffer.
On the way to the parser, each `String` moves into an `OsString` with no copy, and a small
`Words` type wipes them all in its `Drop`.

In Kotlin you might reach for `generateSequence` or a `Regex`, but a quoting rule with escapes
is clearer as an explicit `when (mode)` inside a `for (c in line)` loop: the same state machine.

### 4. Keeping per-line state out of the long-lived struct

The `Shell` struct lives as long as the shell does, so it holds only what must outlive a line:

```rust
struct Shell<'a> {
    session: Session<FsStore>,
    clock: Box<dyn Clock>,
    env: &'a Env,
    last_active: Duration,
    pending: Option<PendingClear>,
}
```

The typed line, its words and the parsed command are locals inside one turn of the loop. When
the turn ends they drop, and the wiping buffers are wiped. If they were fields, a line typed an
hour ago could still be in memory. Rust's scopes make "this lives for one turn" the default.

The one secret that must outlive a turn is the copied value waiting to be cleared. It lives in
`pending`, in a `Zeroizing<String>`, and `take()` moves it out when the clipboard is cleared, so
it is wiped at that moment rather than left in the struct. Neither `Shell` nor `PendingClear`
derives `Debug`, so neither can be printed by accident.

The same idea keeps the throttle working. The throttle lives in the `Session`, and
`Session::lock` drops only the keys and the data. Because the shell keeps one `Session` and
never builds a new one, three wrong passwords followed by `lock` and `unlock` still wait.

In Kotlin you'd keep the line in a local `val` inside the `while` body for the same reason,
though there the garbage collector, not the scope, decides when it is freed.

## Exercises

1. Make `tokenize` refuse a word longer than 1024 bytes with a new `UsageError`, and add a case
   to `tokenize_quotes_and_escapes`. Check: `cargo test -p holm-cli --locked --test shell
   tokenize`
2. Add a `clear` command that clears the clipboard now if Holm's value is still there, and
   prints "Nothing to clear." otherwise. Test it with `ShellTerm` and `ClipState`. Check:
   `cargo test -p holm-cli --locked --test shell`
3. `ShellTerm` records each deadline it gets in `deadlines`. Test that an open vault with
   nothing on the clipboard gets a deadline about 300 seconds from `Instant::now()`, and that
   after `gen --copy` it is about 30 seconds away. (The test clock does not move by itself, so
   the shell's wait is the whole auto-lock time.) Check: `cargo test -p holm-cli --locked
   --test shell`

## Read next

- [The `loop` keyword](https://doc.rust-lang.org/std/keyword.loop.html)
- [`Option::into_iter`](https://doc.rust-lang.org/std/option/enum.Option.html#method.into_iter)
  and [`Iterator::min`](https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.min)
- [Lesson 34: Moving secrets in and out](34-moving-secrets-in-and-out.md)
