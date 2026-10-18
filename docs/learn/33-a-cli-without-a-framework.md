# Lesson 33: A CLI without a framework

## Why this matters

A password manager's command line has one job that most CLIs never face: it has to ask for a
secret without leaving it anywhere. Shell history keeps argv, `ps` shows argv to other users,
environment variables leak into child processes and crash reports, and a pipe on stdin means a
file somewhere holds the password. So `holm` takes passwords only from the terminal itself, with
echo off, and it has to put the terminal back the way it found it on every exit path. A crate
like `clap` would parse our flags, but it would also hand us a `--password` option one typo away,
and it is a large dependency to vet for a few hundred lines of parsing. Holm writes its own.

## What we built

`crates/holm-platform/src/tty.rs` (feature `tty`) opens `/dev/tty`, switches it to raw mode with
rustix's safe termios API, and runs a small line editor that fills one pre-sized wiping buffer.
`crates/holm-cli` is the `holm` binary: `args.rs` parses the command line and refuses anything
that looks like a password flag, `term.rs` puts the terminal behind a trait, `vault.rs` takes the
instance lock and asks for the master password up to three times, and `commands/read.rs` runs
`init`, `list`, `get` and `gen`. `get` prints every secret field as `(hidden)`.

## Rust ideas in this task

### 1. `OsString` and `args_os`

`std::env::args()` panics if an argument is not valid Unicode. `args_os()` hands back
`OsString`s, the platform's own bytes, so a strange file name in `--vault` cannot crash Holm:

```rust
fn main() -> ExitCode {
    // The arguments are the only thing read from the process environment.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    // ...
}
```

A path stays an `OsString` all the way to `PathBuf`. Text that must be text, like a search
term, is converted with a fixed error and no lossy guess:

```rust
fn text(arg: &OsStr) -> Result<&str, UsageError> {
    arg.to_str().ok_or(NOT_TEXT)
}
```

Kotlin: `main(args: Array<String>)` has already decoded the bytes for you; the JVM replaces bad
bytes silently. Rust makes you choose.

### 2. Matching on slices of arguments

A slice pattern names the first few elements and binds the rest. Each loop turn eats one flag
(and its value) and continues with the tail:

```rust
loop {
    rest = match rest {
        [] => break,
        [flag, value, tail @ ..] if flag == "--search" => {
            set_once(&mut search, Zeroizing::new(text(value)?.to_owned()))?;
            tail
        }
        [flag, tail @ ..] if flag == "--trash" => {
            set_flag(&mut trash)?;
            tail
        }
        [flag] if ["--search", "--type", "--category", "--sort"]
            .iter()
            .any(|f| flag == *f) =>
        {
            return Err(MISSING_VALUE);
        }
        [first, ..] => return Err(unexpected(first)),
    };
}
```

The compiler checks the arms cover every length: `[]`, one element, and two or more. A flag at
the end with no value falls into the `[flag]` arm instead of reading past the end. `OsString`
compares with `&str` directly, so no conversion happens before a flag is recognised.

Kotlin: the nearest is `when` over `args[i]` with a manual index, where `args[i + 1]` can throw.
Here the shape of the slice is the bounds check.

### 3. A trait object for the terminal

The commands never call `holm_platform::tty` directly. They take `&mut dyn Terminal`:

```rust
pub trait Terminal {
    fn secret(&mut self, prompt: &str, max_bytes: usize) -> Result<Zeroizing<String>, TtyError>;
    fn line(&mut self, prompt: &str, max_bytes: usize, deadline: Option<Instant>)
        -> Result<Option<Zeroizing<String>>, TtyError>;
    fn wait_for_key(&mut self, until: Instant) -> Result<bool, TtyError>;
}
```

`main.rs` passes `RealTerminal`. The tests pass a `FakeTerminal` that answers from a queue and
records every prompt, so a test can say "the second instance was refused before any prompt":

```rust
impl Terminal for FakeTerminal {
    fn secret(&mut self, prompt: &str, _max_bytes: usize) -> Result<Zeroizing<String>, TtyError> {
        self.prompts.push((Kind::Secret, prompt.to_owned()));
        self.answers.pop_front().map(Zeroizing::new).ok_or(TtyError::Cancelled)
    }
    // ...
}
```

`dyn Terminal` is a fat pointer (data plus vtable), the same idea as a Kotlin interface
reference. `out` and `err` are `&mut dyn Write` for the same reason: tests read `Vec<u8>`s.

Kotlin: an `interface Terminal` with a fake class in the test source set.

### 4. RAII guards that restore state in `Drop`

Raw mode must end however `read_line` ends: `Ok`, an `Err` from `?`, or a panic. The saved mode
lives in a guard, and the guard's `Drop` puts it back:

```rust
struct ModeGuard<'a> {
    tty: &'a File,
    saved: Termios,
    flush_input: bool,
}

impl Drop for ModeGuard<'_> {
    fn drop(&mut self) {
        // Errors are dropped on purpose: there is nothing better to do while
        // returning or unwinding, and the restore is still tried.
        if self.flush_input {
            let _ = tcflush(self.tty, QueueSelector::IFlush);
        }
        let _ = tcsetattr(self.tty, OptionalActions::Now, &self.saved);
    }
}
```

The guard is built from the saved copy before raw mode is switched on, so even a failing
`tcsetattr` leaves something that restores. `flush_input` is set after Ctrl-C or an over-long
line, so the rest of a pasted password is thrown away instead of reaching the shell.

The same pattern holds the vault: `Opened` owns the session and the `holm.lock` guard, and its
`Drop` locks the session. Fields drop in declaration order, so the session (declared first) is
wiped before the lock is released.

What `Drop` cannot do: run when the process is killed. A `kill` from outside ends Holm without
unwinding, and the terminal can stay with echo off until you type `stty sane`. Catching signals
safely needs `unsafe` or another crate, so Holm documents the gap instead (`docs/CRYPTO.md`).

Kotlin: `use {}` on a `Closeable`, or `try { } finally { }`. Rust needs no keyword: leaving the
scope is enough.

### 5. `ExitCode` instead of `process::exit`

`main` returns `ExitCode`. Returning, unlike `std::process::exit`, runs every destructor first,
so guards, locks and wiping buffers all finish:

```rust
match dispatch(inv, env, term, out, err) {
    Ok(()) => ExitCode::SUCCESS,
    Err(CliError::Usage(e)) => usage_error(&e, err),
    Err(e) => {
        let _ = writeln!(err, "holm: {e}");
        ExitCode::from(e.exit_code())
    }
}
```

0 is success, 1 a failure, 2 a usage error. Every `CliError` has fixed `Display` text: never a
path, a typed value or a library message.

Kotlin: `exitProcess(code)` skips `finally` blocks on other threads and shutdown order is up to
the JVM. Returning a value from `main` keeps the cleanup in your hands.

## Exercises

1. Add a test to `tty::tests` that Ctrl-D in the middle of a line is ignored: the bytes
   `a 0x04 b CR` give `"ab"`. Check:
   `cargo test -p holm-platform --features tty --locked tty`
2. Add a test to `args::tests` that `list --sort` with no value is `MISSING_VALUE` and that
   `list --trash --trash` is `REPEATED_FLAG`. Check:
   `cargo test -p holm-cli --locked --lib args`
3. Write a test in `tests/read_commands.rs` that runs `init` with an empty `FakeTerminal` queue
   and checks for exit 1, "Cancelled" on stderr, one prompt recorded, and no vault file. Check:
   `cargo test -p holm-cli --locked --test read_commands init_`

## Read next

- [std::process::ExitCode](https://doc.rust-lang.org/std/process/struct.ExitCode.html)
- [rustix::termios](https://docs.rs/rustix/1.1.5/rustix/termios/index.html)
- [Lesson 32: Building output safely](32-building-output-safely.md)
