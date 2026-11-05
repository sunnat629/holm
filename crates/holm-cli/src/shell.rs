//! `holm shell`: many commands with one unlock, in one process.
//!
//! The shell takes the vault folder's instance lock once and holds it until it ends.
//! It keeps one [`Session`] for its whole life, so the unlock throttle outlives a
//! lock: locking drops only the keys and the data.
//!
//! Each prompt waits with a deadline: the earlier of the auto-lock time and a pending
//! clipboard clear. When the prompt returns (a line, or the deadline), the shell
//! first asks the session whether the idle time has passed and locks if so, so a
//! line typed after the idle time runs against a locked vault. Then it clears the
//! clipboard if its time has come and it still holds Holm's value.
//!
//! A command's own prompts (hidden fields, `Type … to continue`, the discard prompt)
//! wait with a deadline too: the auto-lock time from when the prompt starts. If it
//! passes, the command is cancelled and the shell idle-locks before the line counts
//! as activity.
//!
//! The shell also locks when the computer has slept (the vault's `lock_on_sleep`,
//! on by default). A [`SleepWatch`] notes both clocks; on macOS the monotonic clock
//! stops during sleep, so a wall clock that gained more than a few seconds on it means
//! the computer slept. Every prompt that has something to protect (an open vault or a
//! clipboard value) is given an interrupt that asks the watch about every 0.1 s, so
//! the lock comes on waking, not at the next Enter. A line typed before the sleep is
//! wiped and never runs.
//!
//! The same interrupt also reads the owner of `/dev/console`, at most once a second.
//! Fast user switching and the login window hand the console to another user (root
//! for the login window), so a new owner locks the shell just as a sleep does. The
//! owner is noted at shell start and again at each unlock; an owner that can't be
//! read is no change. The shell has no event loop, so it can't hear a screen lock
//! (Ctrl-Cmd-Q) that neither sleeps nor switches users; the GUI can
//! (`docs/CRYPTO.md`).
//!
//! Typed lines can hold secrets by mistake, so there is no history, and every line
//! and word lives in a buffer that is wiped when dropped. Passwords are never read
//! from a line: the commands ask for them at hidden prompts, as one-shot commands do.

use std::cell::Cell;
use std::ffi::OsString;
use std::io::Write;
use std::mem;
use std::path::Path;
use std::process::ExitCode;
use std::rc::Rc;
use std::time::{Duration, Instant};

use holm_core::clock::{Clock, SleepWatch};
use holm_core::rules::MAX_LINE_BYTES;
use holm_core::session::Session;
use holm_core::settings::{
    AUTO_LOCK_DEFAULT_SECS, AUTO_LOCK_MAX_SECS, AUTO_LOCK_MIN_SECS, CLIPBOARD_DEFAULT_SECS,
    CLIPBOARD_MAX_SECS, CLIPBOARD_MIN_SECS,
};
use holm_platform::fs_store::FsStore;
use holm_platform::tty::TtyError;
use zeroize::{Zeroize, Zeroizing};

use crate::args::{Command, CopyField, TOO_MANY, UsageError, parse_command};
use crate::commands::copy::{self, Clip};
use crate::commands::{read, transfer, write};
use crate::output::CliError;
use crate::term::{Interrupt, Terminal};
use crate::vault::{self, WRONG_PASSWORD};
use crate::{Env, USAGE};
use holm_platform::clip_clear::PendingClear;

/// The prompt while the vault is open.
pub const PROMPT: &str = "holm> ";
/// The prompt while the vault is locked.
pub const LOCKED_PROMPT: &str = "holm (locked)> ";
/// The longest line the prompt takes.
pub const MAX_SHELL_LINE_BYTES: usize = 4096;
/// A quote with no closing quote.
pub const UNCLOSED_QUOTE: UsageError = UsageError("A quote isn't closed. Nothing was run.");
/// A backslash with nothing after it.
pub const TRAILING_BACKSLASH: UsageError =
    UsageError("The line ends with a backslash. Nothing was run.");

/// Shown when a command needs the vault and it is locked.
const LOCKED: &str = "The vault is locked. Type unlock to open it.";
/// Shown for `init` and `shell` inside the shell.
const NOT_IN_SHELL: &str = "That command doesn't run inside the shell.";
/// The visible prompt before a lock that would lose unsaved changes.
const DISCARD_PROMPT: &str = "Type discard to lock without saving: ";
/// Added to a lock message when unsaved changes were dropped.
const DISCARDED: &str = " Unsaved changes were discarded.";
/// The lock message after the computer slept.
const SLEEP_LOCKED: &str = "Locked because the computer slept.";
/// The lock message after another user (or the login window) took the screen.
const USER_LOCKED: &str = "Locked because the Mac switched to another user or the login window.";
/// A waiting prompt reads `/dev/console`'s owner at most this often.
const CONSOLE_EVERY: Duration = Duration::from_secs(1);
/// A deadline is never closer than this, so a clock that lags by a moment can't
/// make the prompt spin.
const MIN_WAIT: Duration = Duration::from_millis(200);

/// The shell's help, printed before the one-shot commands' options.
const SHELL_HELP: &str = "\
Commands in the shell:
  unlock                    Open the vault.
  lock                      Lock the vault. The shell keeps running.
  exit, quit                Lock the vault and leave. Ctrl-D (or Ctrl-C) at
                            the prompt does the same.
  help                      Show this help.
  list, get, gen, add, edit, rm, restore, empty-trash, passwd, import, export, version
                            As below, without holm and --vault.

The vault locks itself after its auto-lock time without use. Quote a word that
has spaces: add note --title \"My note\". Never type a password on a line; Holm
asks for it at a hidden prompt.

";

// ----- the tokenizer -----

/// Where the tokenizer is in a line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Between words.
    Gap,
    /// In a word, outside quotes.
    Word,
    /// Inside `'…'`: every character is literal, a backslash too.
    Single,
    /// Inside `"…"`: a backslash takes the next character as it is.
    Double,
}

/// Splits a shell line into words.
///
/// Whitespace splits words. `'…'` and `"…"` group, and can sit inside a word
/// (`a'b c'` is one word, `ab c`). Outside single quotes, `\` takes the next
/// character as it is. Every word is built at its final size in a wiping buffer, so
/// no copy of the line is left behind in freed memory.
///
/// # Errors
/// [`UNCLOSED_QUOTE`] or [`TRAILING_BACKSLASH`].
pub fn tokenize(line: &str) -> Result<Vec<Zeroizing<String>>, UsageError> {
    // All words, end to end, then where each one starts and ends. The buffer never
    // grows past the line's length, so it never moves.
    let mut all = Zeroizing::new(String::with_capacity(line.len()));
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut mode = Mode::Gap;
    let mut start = 0;
    let mut escaped = false;
    for c in line.chars() {
        if escaped {
            all.push(c);
            escaped = false;
            continue;
        }
        match (mode, c) {
            (Mode::Single, '\'') | (Mode::Double, '"') => mode = Mode::Word,
            (Mode::Double, '\\') => escaped = true,
            (Mode::Single | Mode::Double, c) => all.push(c),
            (Mode::Gap, c) if c.is_whitespace() => {}
            (Mode::Word, c) if c.is_whitespace() => {
                spans.push((start, all.len()));
                mode = Mode::Gap;
            }
            (Mode::Gap | Mode::Word, c) => {
                if mode == Mode::Gap {
                    start = all.len();
                    mode = Mode::Word;
                }
                match c {
                    '\'' => mode = Mode::Single,
                    '"' => mode = Mode::Double,
                    '\\' => escaped = true,
                    c => all.push(c),
                }
            }
        }
    }
    if escaped {
        return Err(TRAILING_BACKSLASH);
    }
    match mode {
        Mode::Single | Mode::Double => return Err(UNCLOSED_QUOTE),
        Mode::Word => spans.push((start, all.len())),
        Mode::Gap => {}
    }
    Ok(spans
        .into_iter()
        .map(|(a, b)| {
            let mut word = String::with_capacity(b - a);
            word.push_str(&all[a..b]);
            Zeroizing::new(word)
        })
        .collect())
}

/// Words handed to [`parse_command`]. Each `String` moves into an `OsString` without
/// a copy, and is wiped when this drops.
struct Words(Vec<OsString>);

impl Words {
    fn new(words: Vec<Zeroizing<String>>) -> Words {
        Words(
            words
                .into_iter()
                .map(|mut w| OsString::from(mem::take(&mut *w)))
                .collect(),
        )
    }
}

impl Drop for Words {
    fn drop(&mut self) {
        for word in self.0.drain(..) {
            // Every word came from a `String`, so this always gets it back.
            if let Ok(mut s) = word.into_string() {
                s.zeroize();
            }
        }
    }
}

// ----- prompts inside a command -----

/// Why the shell locks on its own, apart from the idle time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Away {
    /// The computer slept.
    Slept,
    /// `/dev/console` changed owner: fast user switching or the login window.
    UserChanged,
}

/// What a waiting prompt asks to tell that the user went away: the sleep watch and
/// the owner of `/dev/console`. No `Debug`: it holds closures, not data worth showing.
#[derive(Clone)]
struct AwayCheck {
    clock: Rc<dyn Clock>,
    /// Both clocks as of the last wake.
    watch: SleepWatch,
    /// Reads `/dev/console`'s owner; None when it can't be read.
    console: Rc<dyn Fn() -> Option<u32>>,
    /// The owner as of shell start or the last unlock; None when it couldn't be read,
    /// and then no owner change is ever seen.
    owner: Option<u32>,
}

impl AwayCheck {
    /// Both checks, now. For the moment after a prompt returns.
    fn now(&self) -> Option<Away> {
        if self.watch.slept(self.clock.as_ref()) {
            return Some(Away::Slept);
        }
        self.user_changed().then_some(Away::UserChanged)
    }

    /// Both checks, for an interrupt asked about every 0.1 s: the console is read at
    /// most once per [`CONSOLE_EVERY`], counted from `last` (the first ask reads it).
    fn poll(&self, last: &Cell<Option<Duration>>) -> Option<Away> {
        if self.watch.slept(self.clock.as_ref()) {
            return Some(Away::Slept);
        }
        let mono = self.clock.monotonic();
        if last
            .get()
            .is_some_and(|then| mono.saturating_sub(then) < CONSOLE_EVERY)
        {
            return None;
        }
        last.set(Some(mono));
        self.user_changed().then_some(Away::UserChanged)
    }

    /// Whether `/dev/console` has another owner now. An owner that can't be read,
    /// then or now, is no change: an error never locks.
    fn user_changed(&self) -> bool {
        let Some(was) = self.owner else {
            return false;
        };
        (self.console)().is_some_and(|now| now != was)
    }
}

/// Runs `ask` with an interrupt made from `away` (none if `away` is None). Returns
/// its answer and why the interrupt fired, if it did.
fn ask_with_away<T>(
    away: Option<&AwayCheck>,
    ask: impl FnOnce(Interrupt<'_>) -> T,
) -> (T, Option<Away>) {
    let fired = Cell::new(None);
    let last = Cell::new(None);
    let check = || match away.and_then(|a| a.poll(&last)) {
        Some(why) => {
            fired.set(Some(why));
            true
        }
        None => false,
    };
    let interrupt: Interrupt<'_> = if away.is_some() { Some(&check) } else { None };
    let answer = ask(interrupt);
    (answer, fired.get())
}

/// The terminal as a command inside the shell sees it. While the vault is open,
/// every prompt gives up after the auto-lock time, counted from when the prompt
/// starts, so a user who keeps answering is never cut off. While lock-on-sleep is
/// armed, every prompt also stops when the computer has slept or another user took
/// the screen. No `Debug`: it is only a view of the terminal.
struct IdleTerm<'t> {
    term: &'t mut dyn Terminal,
    /// The auto-lock time while the vault is open; None while it is locked.
    limit: Option<Duration>,
    /// Set when a prompt's idle deadline passed. The command saw a cancel.
    timed_out: bool,
    /// The sleep and console checks; None when lock-on-sleep is not armed for this
    /// line.
    away: Option<AwayCheck>,
    /// Set when a prompt stopped because the user went away. The command saw a
    /// cancel.
    went_away: Option<Away>,
}

impl IdleTerm<'_> {
    /// Runs `ask` with this line's away interrupt (if armed). Returns its answer and
    /// why the interrupt fired, if it did.
    fn with_interrupt<T>(
        &mut self,
        ask: impl FnOnce(&mut dyn Terminal, Interrupt<'_>) -> T,
    ) -> (T, Option<Away>) {
        let term = &mut *self.term;
        ask_with_away(self.away.as_ref(), |interrupt| ask(term, interrupt))
    }

    /// The away interrupt fired: note why and cancel the command. Whatever came back
    /// is dropped (and wiped).
    fn away_cancel<T>(&mut self, why: Away) -> Result<T, TtyError> {
        self.went_away = Some(why);
        Err(TtyError::Cancelled)
    }

    /// The idle deadline for a prompt that starts now.
    fn idle_deadline(&self) -> Option<Instant> {
        self.limit.map(|limit| Instant::now() + limit)
    }

    /// A prompt that came back empty: if the idle deadline is what ended it, note
    /// the time-out and cancel the command; else hand the empty answer back.
    fn ended<T>(
        &mut self,
        answer: Option<T>,
        asked: Option<Instant>,
        idle: Option<Instant>,
    ) -> Result<Option<T>, TtyError> {
        // The idle deadline ended it if it came no later than the caller's own.
        let idle_ended = idle.is_some_and(|i| asked.is_none_or(|a| i <= a));
        if answer.is_none() && idle_ended {
            self.timed_out = true;
            return Err(TtyError::Cancelled);
        }
        Ok(answer)
    }
}

impl Terminal for IdleTerm<'_> {
    fn secret(&mut self, prompt: &str, max_bytes: usize) -> Result<Zeroizing<String>, TtyError> {
        self.secret_until(prompt, max_bytes, None)?
            .ok_or(TtyError::Cancelled)
    }

    fn secret_until(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        let idle = self.idle_deadline();
        let until = earlier(deadline, idle);
        let (answer, fired) = self.with_interrupt(|term, interrupt| {
            term.secret_interruptible(prompt, max_bytes, until, interrupt)
        });
        if let Some(why) = fired {
            drop(answer);
            return self.away_cancel(why);
        }
        self.ended(answer?, deadline, idle)
    }

    fn line(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        let idle = self.idle_deadline();
        let until = earlier(deadline, idle);
        let (answer, fired) = self.with_interrupt(|term, interrupt| {
            term.line_interruptible(prompt, max_bytes, until, interrupt)
        });
        if let Some(why) = fired {
            drop(answer);
            return self.away_cancel(why);
        }
        self.ended(answer?, deadline, idle)
    }

    fn wait_for_key(&mut self, until: Instant) -> Result<bool, TtyError> {
        let (pressed, fired) = self
            .with_interrupt(|term, interrupt| term.wait_for_key_interruptible(until, interrupt));
        if let Some(why) = fired {
            return self.away_cancel(why);
        }
        pressed
    }
}

/// The earlier of two deadlines, or None if neither is set.
fn earlier(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    a.into_iter().chain(b).min()
}

// ----- the shell -----

/// A copied value waiting to be cleared from the clipboard. No `Debug`: it holds the
/// value.
struct Pending {
    clip: Box<dyn Clip>,
    clear: PendingClear,
}

/// What the loop does after a line.
enum Flow {
    Continue,
    Exit,
}

/// How a lock was asked for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LockReason {
    /// `lock`, `exit` or `quit`: a refusal at the discard prompt keeps the vault open.
    Command,
    /// Ctrl-D or Ctrl-C at the prompt: if the input ends at the discard prompt too
    /// (Ctrl-D, or the terminal is gone), the changes are dropped. Ctrl-C there keeps
    /// the vault open.
    EndOfInput,
}

/// The shell's state. No `Debug`: it holds the session and maybe a copied value.
struct Shell<'a> {
    session: Session<FsStore>,
    /// The shell's own clock, for prompt deadlines and the sleep check. The session
    /// keeps its own and decides on its own whether the idle time has passed. Shared
    /// with each line's [`IdleTerm`], which asks it while a prompt waits.
    clock: Rc<dyn Clock>,
    /// Both clocks as of the last wake, to tell that the computer slept since.
    watch: SleepWatch,
    /// `/dev/console`'s owner at shell start or the last unlock; None if it couldn't
    /// be read.
    console_owner: Option<u32>,
    env: &'a Env,
    /// When the last line was read, on the shell's clock.
    last_active: Duration,
    pending: Option<Pending>,
}

/// Runs `holm shell` on the vault at `path` and returns the exit code: 0 after
/// `exit`, `quit` or Ctrl-D, 1 if the shell could not start or the terminal failed.
pub fn run_shell(
    path: &Path,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    crate::finish(shell(path, env, term, out, err), err)
}

/// [`run_shell`] as a result.
///
/// # Errors
/// The folder and lock errors of [`vault::lock_folder`], [`CliError::NoVault`]
/// before any prompt, or a terminal error at the prompt.
pub(crate) fn shell(
    path: &Path,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let _lock = vault::lock_folder(path)?;
    if !vault::exists(path) {
        return Err(CliError::NoVault);
    }
    let clock: Rc<dyn Clock> = Rc::from((env.clock)());
    let mut sh = Shell {
        session: Session::new(FsStore::new(path), (env.clock)()),
        last_active: clock.monotonic(),
        watch: SleepWatch::new(clock.as_ref()),
        console_owner: (env.console_owner)(),
        clock,
        env,
        pending: None,
    };
    let result = sh.run(term, out, err);
    sh.close(err);
    result
    // `_lock` drops last: the session is locked before another Holm can open it.
}

impl Shell<'_> {
    fn run(
        &mut self,
        term: &mut dyn Terminal,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<(), CliError> {
        writeln!(err, "Type help to see the commands, and exit to leave.")?;
        let unlocked = self.unlock(term, err);
        report(unlocked, err)?;
        loop {
            let prompt = if self.session.is_unlocked() {
                PROMPT
            } else {
                LOCKED_PROMPT
            };
            let away = self.sleep_armed().then(|| self.away_check());
            let deadline = self.deadline();
            let (read, fired) = ask_with_away(away.as_ref(), |interrupt| {
                term.line_interruptible(prompt, MAX_SHELL_LINE_BYTES, deadline, interrupt)
            });
            // A sleep or user switch lock, an idle lock or a clipboard clear, before
            // the line counts. A line stopped by the away check came back as `Ok(None)`
            // and was already wiped.
            self.on_wake(err, fired)?;
            let line = match read {
                // The deadline passed; `on_wake` did what was due.
                Ok(None) => continue,
                Ok(Some(line)) => line,
                // Ctrl-D, Ctrl-C or a closed terminal: leave, as `exit` does.
                Err(TtyError::Cancelled | TtyError::EndOfInput) => {
                    let mut term = self.idle_term(term);
                    if self.lock(LockReason::EndOfInput, &mut term, err)? {
                        return Ok(());
                    }
                    continue;
                }
                Err(e @ (TtyError::TooLong | TtyError::NotUtf8)) => {
                    writeln!(err, "holm: {}", CliError::from(e))?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let flow = self.line(&line, term, out, err);
            drop(line);
            match flow? {
                Flow::Continue => {}
                Flow::Exit => return Ok(()),
            }
        }
    }

    /// Runs one typed line. Errors from the command are printed here; only an
    /// output error comes back.
    fn line(
        &mut self,
        line: &str,
        term: &mut dyn Terminal,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<Flow, CliError> {
        let mut flow = Flow::Continue;
        let mut term = self.idle_term(term);
        let term = &mut term;
        let result = match tokenize(line) {
            Err(e) => Err(CliError::Usage(e)),
            Ok(words) => match words.first().map(|w| w.as_str()) {
                None => Ok(()),
                Some("exit" | "quit") if words.len() == 1 => {
                    if self.lock(LockReason::Command, term, err)? {
                        flow = Flow::Exit;
                    }
                    Ok(())
                }
                Some("lock") if words.len() == 1 => {
                    if self.session.is_unlocked() {
                        self.lock(LockReason::Command, term, err).map(|_| ())
                    } else {
                        self.clear_clipboard(err)?;
                        writeln!(err, "The vault is already locked.").map_err(CliError::from)
                    }
                }
                Some("unlock") if words.len() == 1 => self.unlock(term, err),
                Some("help" | "--help" | "-h") if words.len() == 1 => {
                    write!(out, "{SHELL_HELP}{USAGE}").map_err(CliError::from)
                }
                Some("exit" | "quit" | "lock" | "unlock" | "help" | "--help" | "-h") => {
                    Err(CliError::Usage(TOO_MANY))
                }
                Some("init" | "shell") => {
                    writeln!(err, "holm: {NOT_IN_SHELL}").map_err(CliError::from)
                }
                Some(_) => {
                    let words = Words::new(words);
                    match parse_command(&words.0) {
                        Ok(command) => {
                            drop(words);
                            self.command(command, term, out, err)
                        }
                        Err(e) => Err(CliError::Usage(e)),
                    }
                }
            },
        };
        let failed = result.is_err();
        if let Some(why) = term.went_away {
            // The computer slept or another user took the screen at one of the
            // command's prompts. Lock now; the lock message says why the command
            // stopped, so its cancel is not printed.
            self.away_lock(why, err)?;
            if !matches!(result, Err(CliError::Cancelled)) {
                report(result, err)?;
            }
        } else if term.timed_out {
            // The user walked away at one of the command's prompts. Lock now, before
            // `after_line` counts the line as activity. The lock message says why
            // the command stopped, so its cancel is not printed.
            self.idle_lock(err)?;
            if !matches!(result, Err(CliError::Cancelled)) {
                report(result, err)?;
            }
        } else {
            report(result, err)?;
        }
        self.after_line(failed, err)?;
        Ok(flow)
    }

    /// Runs one parsed command. The master password is not asked again, except
    /// where the spec asks for it: `export` (again), `passwd` (the current one) and
    /// copying a recovery phrase.
    fn command(
        &mut self,
        command: Command,
        term: &mut dyn Terminal,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<(), CliError> {
        let session = &mut self.session;
        match command {
            Command::Help => {
                write!(out, "{SHELL_HELP}{USAGE}")?;
                Ok(())
            }
            Command::Version => {
                writeln!(out, "holm {}", env!("CARGO_PKG_VERSION"))?;
                Ok(())
            }
            Command::Gen(args) if args.copy => {
                let clip = copy::open_clip(self.env)?;
                let value = copy::gen_secret(args.kind)?;
                let secs = self.clear_secs();
                self.copy(clip, value, secs, err)
            }
            Command::Gen(args) => read::gen_value(&args, out),
            Command::Init | Command::Shell => {
                writeln!(err, "holm: {NOT_IN_SHELL}")?;
                Ok(())
            }
            _ if !session.is_unlocked() => {
                writeln!(err, "{LOCKED}")?;
                Ok(())
            }
            Command::List(args) => read::list(session, &args, out),
            Command::Get(args) => match args.copy {
                Some(field) => self.copy_field(&args.reference, field, term, err),
                None => read::get(session, &args, out),
            },
            Command::Add(args) => write::add_to(session, args, term, out),
            Command::Edit(args) => write::edit_in(session, args, term, out),
            Command::Rm(args) => write::rm_in(session, &args, term, out),
            Command::Restore(args) => write::restore_in(session, &args, out),
            Command::EmptyTrash => write::empty_trash_in(session, term, out),
            Command::Passwd => write::passwd_in(session, self.env, term, out, err),
            Command::Import(args) => {
                let batch = transfer::read_import(&args)?;
                transfer::import_into(session, batch, term, out, err)
            }
            Command::Export(args) => {
                let file = transfer::export_target(&args)?;
                transfer::export_to(session, &file, args.backup, args.format, term, out, err)
            }
        }
    }

    /// `unlock`: one try. A throttle wait is reported before any prompt.
    fn unlock(&mut self, term: &mut dyn Terminal, err: &mut dyn Write) -> Result<(), CliError> {
        if self.session.is_unlocked() {
            writeln!(err, "The vault is already open.")?;
            return Ok(());
        }
        if let Some(wait) = self.session.throttle_status().retry_after {
            return Err(CliError::Throttled {
                retry_after_secs: ceil_secs(wait),
            });
        }
        if vault::unlock_once(&mut self.session, term)? {
            self.last_active = self.clock.monotonic();
            // A sleep before this unlock has nothing left to lock, and whoever owns
            // the console now is the one the password was typed for.
            self.watch.mark(self.clock.as_ref());
            self.console_owner = (self.env.console_owner)();
        } else {
            writeln!(err, "{WRONG_PASSWORD}")?;
        }
        Ok(())
    }

    /// Locks for `lock`, `exit` or the end of input, and says so. Unsaved changes get
    /// one more save; if that fails, `discard` must be typed first. Returns false if
    /// the vault stays open. A locked vault only has its clipboard value cleared.
    fn lock(
        &mut self,
        reason: LockReason,
        term: &mut IdleTerm<'_>,
        err: &mut dyn Write,
    ) -> Result<bool, CliError> {
        if !self.session.is_unlocked() {
            self.clear_clipboard(err)?;
            return Ok(true);
        }
        if self.session.is_dirty() && self.session.save().is_err() {
            writeln!(err, "holm: {}", CliError::NotSaved)?;
            let answer = term.line(DISCARD_PROMPT, MAX_LINE_BYTES, None);
            if let Some(why) = term.went_away {
                // The computer slept or another user took the screen at this prompt:
                // an away lock, which discards without asking.
                drop(answer);
                self.away_lock(why, err)?;
                return Ok(true);
            }
            match answer {
                Ok(Some(typed)) if typed.trim() == "discard" => {}
                // Nobody answered within the auto-lock time: an idle lock, which
                // discards without asking.
                Err(_) if term.timed_out => {
                    self.idle_lock(err)?;
                    return Ok(true);
                }
                // The input has ended (Ctrl-D again) or the terminal is gone, so
                // nobody can be asked. Ctrl-C, a refusal or a bad line keep it open.
                Err(TtyError::EndOfInput | TtyError::Io(_) | TtyError::NoTerminal)
                    if reason == LockReason::EndOfInput => {}
                _ => {
                    writeln!(err, "Not locked.")?;
                    return Ok(false);
                }
            }
        }
        self.clear_clipboard(err)?;
        let outcome = self.session.lock();
        let tail = if outcome.discarded_unsaved {
            DISCARDED
        } else {
            ""
        };
        writeln!(err, "Locked.{tail}")?;
        Ok(true)
    }

    /// After a prompt returns: an away lock if the prompt's interrupt `fired` (its
    /// answer counts, even if the clocks no longer show the sleep) or, if it didn't,
    /// if the computer slept or the console changed owner since (and `lock_on_sleep`
    /// is on); then an idle lock if the time has passed; then a clipboard clear if one
    /// is due.
    fn on_wake(&mut self, err: &mut dyn Write, fired: Option<Away>) -> Result<(), CliError> {
        let why = fired.or_else(|| self.away_check().now());
        self.watch.mark(self.clock.as_ref());
        if let Some(why) = why
            && self.lock_on_sleep()
        {
            self.away_lock(why, err)?;
        }
        if self.session.idle_expired() {
            self.idle_lock(err)?;
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.clear.is_due(self.clock.as_ref()))
        {
            self.clear_clipboard(err)?;
        }
        Ok(())
    }

    /// The idle lock: clears the clipboard, then locks and says so. It never waits
    /// and never asks; unsaved changes are dropped. A locked vault only has its
    /// clipboard value cleared.
    fn idle_lock(&mut self, err: &mut dyn Write) -> Result<(), CliError> {
        let limit = self.auto_lock_secs();
        self.clear_clipboard(err)?;
        if !self.session.is_unlocked() {
            return Ok(());
        }
        let outcome = self.session.lock();
        let tail = if outcome.discarded_unsaved {
            DISCARDED
        } else {
            ""
        };
        writeln!(err, "Locked after {} without use.{tail}", span(limit))?;
        Ok(())
    }

    /// The away lock, after a sleep or a user switch: clears the clipboard, then locks
    /// and says why. Like the idle lock, it never waits and never asks; unsaved changes
    /// are dropped. A locked vault only has its clipboard value cleared.
    fn away_lock(&mut self, why: Away, err: &mut dyn Write) -> Result<(), CliError> {
        self.watch.mark(self.clock.as_ref());
        self.clear_clipboard(err)?;
        if !self.session.is_unlocked() {
            return Ok(());
        }
        let outcome = self.session.lock();
        let tail = if outcome.discarded_unsaved {
            DISCARDED
        } else {
            ""
        };
        let message = match why {
            Away::Slept => SLEEP_LOCKED,
            Away::UserChanged => USER_LOCKED,
        };
        writeln!(err, "{message}{tail}")?;
        Ok(())
    }

    /// The vault's `lock_on_sleep`. While locked the setting can't be read, so it
    /// counts as on: then the sleep check can only clear a waiting clipboard value.
    fn lock_on_sleep(&self) -> bool {
        self.session.settings().map_or(true, |s| s.lock_on_sleep)
    }

    /// Whether prompts should stop when the computer has slept: `lock_on_sleep` is
    /// on and there is something to protect (an open vault or a clipboard value).
    /// Otherwise a prompt waits as before, and a sleep is still noticed on the next
    /// line.
    fn sleep_armed(&self) -> bool {
        self.lock_on_sleep() && (self.session.is_unlocked() || self.pending.is_some())
    }

    /// `term` for a command's own prompts: while the vault is open, each one gives
    /// up after the auto-lock time, and while lock-on-sleep is armed, each one stops
    /// when the computer has slept.
    fn idle_term<'t>(&self, term: &'t mut dyn Terminal) -> IdleTerm<'t> {
        let limit = self
            .session
            .is_unlocked()
            .then(|| Duration::from_secs(u64::from(self.auto_lock_secs())));
        IdleTerm {
            term,
            limit,
            timed_out: false,
            away: self.sleep_armed().then(|| self.away_check()),
            went_away: None,
        }
    }

    /// The sleep and console checks as of now, for one prompt or one line.
    fn away_check(&self) -> AwayCheck {
        AwayCheck {
            clock: Rc::clone(&self.clock),
            watch: self.watch,
            console: Rc::clone(&self.env.console_owner),
            owner: self.console_owner,
        }
    }

    /// After every line: the session notes activity, and any change still unsaved
    /// gets one more save, so the vault is never dirty at a prompt if a save can
    /// succeed.
    fn after_line(&mut self, failed: bool, err: &mut dyn Write) -> Result<(), CliError> {
        self.session.note_activity();
        self.last_active = self.clock.monotonic();
        // A failed command already said what went wrong.
        if self.session.is_dirty() && self.session.save().is_err() && !failed {
            writeln!(err, "holm: {}", CliError::NotSaved)?;
        }
        Ok(())
    }

    /// `get REF --copy FIELD`: copies and returns to the prompt at once. The clear
    /// is scheduled for the vault's clear time.
    fn copy_field(
        &mut self,
        reference: &str,
        field: CopyField,
        term: &mut dyn Terminal,
        err: &mut dyn Write,
    ) -> Result<(), CliError> {
        let clip = copy::open_clip(self.env)?;
        let id = vault::resolve_any(&self.session, reference)?;
        let value = copy::value_of(&mut self.session, id, field, term)?;
        let secs = self.clear_secs();
        self.copy(clip, value, secs, err)
    }

    /// Puts `value` on the clipboard and schedules its clear. A value copied before
    /// is replaced on the clipboard, so its clear is dropped.
    fn copy(
        &mut self,
        mut clip: Box<dyn Clip>,
        value: Zeroizing<String>,
        secs: u32,
        err: &mut dyn Write,
    ) -> Result<(), CliError> {
        clip.set(&value).map_err(|_| CliError::CopyFailed)?;
        self.pending = Some(Pending {
            clip,
            clear: PendingClear::new(value, secs, self.clock.as_ref()),
        });
        writeln!(err, "Copied. Holm clears the clipboard in {secs} seconds.")?;
        Ok(())
    }

    /// Clears the clipboard if a copy is pending and it still holds Holm's value or
    /// can't be read ([`copy::clear_copied`]). The value is wiped either way.
    fn clear_clipboard(&mut self, err: &mut dyn Write) -> Result<(), CliError> {
        let Some(mut p) = self.pending.take() else {
            return Ok(());
        };
        match copy::clear_copied(p.clip.as_mut(), p.clear.value()) {
            Ok(said) => writeln!(err, "{said}")?,
            Err(e) => writeln!(err, "holm: {e}")?,
        }
        Ok(())
    }

    /// Locks and clears without asking, as the shell ends. Errors are dropped: there
    /// is nobody left to tell.
    fn close(&mut self, err: &mut dyn Write) {
        let _ = self.clear_clipboard(err);
        let _ = self.session.lock();
    }

    /// When the prompt should return on its own: the earlier of the auto-lock time
    /// (while open) and a pending clipboard clear. None while locked with nothing
    /// to clear.
    fn deadline(&self) -> Option<Instant> {
        let idle = self
            .session
            .is_unlocked()
            .then(|| self.last_active + Duration::from_secs(u64::from(self.auto_lock_secs())));
        let clear = self.pending.as_ref().map(|p| p.clear.due());
        // The earlier of the two, or None if neither is set.
        let target = idle.into_iter().chain(clear).min()?;
        let wait = target.saturating_sub(self.clock.monotonic()).max(MIN_WAIT);
        Some(Instant::now() + wait)
    }

    /// The vault's auto-lock time, in the settings range. The default while locked.
    fn auto_lock_secs(&self) -> u32 {
        self.session
            .settings()
            .map_or(AUTO_LOCK_DEFAULT_SECS, |s| s.auto_lock_secs)
            .clamp(AUTO_LOCK_MIN_SECS, AUTO_LOCK_MAX_SECS)
    }

    /// The vault's clipboard clear time, in the settings range. The default while
    /// locked (for `gen --copy`).
    fn clear_secs(&self) -> u32 {
        self.session
            .settings()
            .map_or(CLIPBOARD_DEFAULT_SECS, |s| s.clipboard_clear_secs)
            .clamp(CLIPBOARD_MIN_SECS, CLIPBOARD_MAX_SECS)
    }
}

/// Prints a command's error as fixed text. Only an output error comes back.
fn report(result: Result<(), CliError>, err: &mut dyn Write) -> Result<(), CliError> {
    match result {
        Ok(()) | Err(CliError::Output) => result,
        Err(CliError::Usage(e)) => {
            writeln!(err, "holm: {e}\nType help to see the commands.")?;
            Ok(())
        }
        Err(e) => {
            writeln!(err, "holm: {e}")?;
            Ok(())
        }
    }
}

/// Whole seconds, rounded up, so a wait is never shown shorter than it is.
fn ceil_secs(d: Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0)
}

/// A time span in words: whole minutes when it is a whole number of them.
fn span(secs: u32) -> String {
    match (secs / 60, secs % 60) {
        (1, 0) => "1 minute".to_owned(),
        (m, 0) => format!("{m} minutes"),
        _ => format!("{secs} seconds"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use holm_core::item::Timestamp;

    use super::*;

    /// A clock whose two halves move together by hand (no sleep), in milliseconds.
    #[derive(Clone, Default)]
    struct StepClock(Arc<AtomicU64>);

    impl StepClock {
        fn advance_ms(&self, ms: u64) {
            self.0.fetch_add(ms, Ordering::SeqCst);
        }
    }

    impl Clock for StepClock {
        fn now_unix(&self) -> Timestamp {
            let secs = self.0.load(Ordering::SeqCst) / 1000;
            Timestamp(1_800_000_000 + i64::try_from(secs).unwrap())
        }

        fn monotonic(&self) -> Duration {
            Duration::from_millis(self.0.load(Ordering::SeqCst))
        }
    }

    fn check(clock: &StepClock, reads: &Rc<Cell<u32>>, owner: u32) -> AwayCheck {
        let reads = Rc::clone(reads);
        let console: Rc<dyn Fn() -> Option<u32>> = Rc::new(move || {
            reads.set(reads.get() + 1);
            Some(owner)
        });
        AwayCheck {
            clock: Rc::new(clock.clone()),
            watch: SleepWatch::new(clock),
            console,
            owner: Some(501),
        }
    }

    #[test]
    fn poll_reads_the_console_at_most_once_a_second() {
        let clock = StepClock::default();
        let reads = Rc::new(Cell::new(0));
        let away = check(&clock, &reads, 501);
        let last = Cell::new(None);
        // Ten polls 0.1 s apart: one read at the first, none after.
        for _ in 0..10 {
            assert_eq!(away.poll(&last), None);
            clock.advance_ms(100);
        }
        assert_eq!(reads.get(), 1);
        // A second after the first read, it reads again.
        assert_eq!(away.poll(&last), None);
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn poll_sees_a_new_console_owner() {
        let clock = StepClock::default();
        let reads = Rc::new(Cell::new(0));
        let away = check(&clock, &reads, 0);
        assert_eq!(away.poll(&Cell::new(None)), Some(Away::UserChanged));
        assert_eq!(away.now(), Some(Away::UserChanged));
    }

    #[test]
    fn unreadable_owner_at_start_never_changes() {
        let clock = StepClock::default();
        let reads = Rc::new(Cell::new(0));
        let away = AwayCheck {
            owner: None,
            ..check(&clock, &reads, 0)
        };
        assert_eq!(away.now(), None);
        assert_eq!(reads.get(), 0);
    }

    #[test]
    fn span_reads_as_minutes_when_whole() {
        assert_eq!(span(60), "1 minute");
        assert_eq!(span(300), "5 minutes");
        assert_eq!(span(90), "90 seconds");
    }

    #[test]
    fn ceil_secs_rounds_up() {
        assert_eq!(ceil_secs(Duration::from_secs(2)), 2);
        assert_eq!(ceil_secs(Duration::from_millis(1001)), 2);
        assert_eq!(ceil_secs(Duration::ZERO), 0);
    }

    #[test]
    fn words_give_back_what_they_took() {
        let words = Words::new(tokenize("get 'a b'").unwrap());
        assert_eq!(words.0, [OsString::from("get"), OsString::from("a b")]);
    }
}
