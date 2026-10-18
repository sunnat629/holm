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
//! Typed lines can hold secrets by mistake, so there is no history, and every line
//! and word lives in a buffer that is wiped when dropped. Passwords are never read
//! from a line: the commands ask for them at hidden prompts, as one-shot commands do.

use std::ffi::OsString;
use std::io::Write;
use std::mem;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use holm_core::clock::Clock;
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
use crate::term::Terminal;
use crate::vault::{self, WRONG_PASSWORD};
use crate::{Env, USAGE};

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
  list, get, gen, add, edit, rm, passwd, import, export, version
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

/// The terminal as a command inside the shell sees it. While the vault is open,
/// every prompt gives up after the auto-lock time, counted from when the prompt
/// starts, so a user who keeps answering is never cut off. No `Debug`: it is only a
/// view of the terminal.
struct IdleTerm<'t> {
    term: &'t mut dyn Terminal,
    /// The auto-lock time while the vault is open; None while it is locked.
    limit: Option<Duration>,
    /// Set when a prompt's idle deadline passed. The command saw a cancel.
    timed_out: bool,
}

impl IdleTerm<'_> {
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
        let answer = self
            .term
            .secret_until(prompt, max_bytes, earlier(deadline, idle))?;
        self.ended(answer, deadline, idle)
    }

    fn line(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        let idle = self.idle_deadline();
        let answer = self.term.line(prompt, max_bytes, earlier(deadline, idle))?;
        self.ended(answer, deadline, idle)
    }

    fn wait_for_key(&mut self, until: Instant) -> Result<bool, TtyError> {
        self.term.wait_for_key(until)
    }
}

/// The earlier of two deadlines, or None if neither is set.
fn earlier(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    a.into_iter().chain(b).min()
}

// ----- the shell -----

/// A copied value waiting to be cleared from the clipboard. No `Debug`: it holds the
/// value.
struct PendingClear {
    clip: Box<dyn Clip>,
    value: Zeroizing<String>,
    /// When to clear it, on the shell's clock.
    at: Duration,
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
    /// Ctrl-D or Ctrl-C at the prompt: if the discard prompt can't be read either,
    /// the terminal is gone and the changes are dropped.
    EndOfInput,
}

/// The shell's state. No `Debug`: it holds the session and maybe a copied value.
struct Shell<'a> {
    session: Session<FsStore>,
    /// The shell's own clock, for prompt deadlines. The session keeps its own and
    /// decides on its own whether the idle time has passed.
    clock: Box<dyn Clock>,
    env: &'a Env,
    /// When the last line was read, on the shell's clock.
    last_active: Duration,
    pending: Option<PendingClear>,
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
    let clock = (env.clock)();
    let mut sh = Shell {
        session: Session::new(FsStore::new(path), (env.clock)()),
        last_active: clock.monotonic(),
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
            let read = term.line(prompt, MAX_SHELL_LINE_BYTES, self.deadline());
            self.on_wake(err)?;
            let line = match read {
                // The deadline passed; `on_wake` did what was due.
                Ok(None) => continue,
                Ok(Some(line)) => line,
                // Ctrl-D, Ctrl-C (the terminal can't tell them apart), or a closed
                // terminal: leave, as `exit` does.
                Err(TtyError::Cancelled) => {
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
        if term.timed_out {
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
            Command::Passwd => write::passwd_in(session, self.env, term, out, err),
            Command::Import(args) => {
                let batch = transfer::read_import(&args)?;
                transfer::import_into(session, batch, term, out, err)
            }
            Command::Export(args) => {
                let file = transfer::export_target(&args)?;
                transfer::export_to(session, &file, args.backup, term, out, err)
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
            match write::confirm(term, DISCARD_PROMPT, "discard") {
                Ok(()) => {}
                // Nobody answered within the auto-lock time: an idle lock, which
                // discards without asking.
                Err(_) if term.timed_out => {
                    self.idle_lock(err)?;
                    return Ok(true);
                }
                // The terminal is gone, so nobody can be asked.
                Err(e)
                    if reason == LockReason::EndOfInput && !matches!(e, CliError::NotConfirmed) => {
                }
                Err(_) => {
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

    /// After a prompt returns: an idle lock if the time has passed, then a clipboard
    /// clear if one is due.
    fn on_wake(&mut self, err: &mut dyn Write) -> Result<(), CliError> {
        if self.session.idle_expired() {
            self.idle_lock(err)?;
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|p| self.clock.monotonic() >= p.at)
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

    /// `term` for a command's own prompts: while the vault is open, each one gives
    /// up after the auto-lock time.
    fn idle_term<'t>(&self, term: &'t mut dyn Terminal) -> IdleTerm<'t> {
        let limit = self
            .session
            .is_unlocked()
            .then(|| Duration::from_secs(u64::from(self.auto_lock_secs())));
        IdleTerm {
            term,
            limit,
            timed_out: false,
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
        self.pending = Some(PendingClear {
            clip,
            value,
            at: self.clock.monotonic() + Duration::from_secs(u64::from(secs)),
        });
        writeln!(err, "Copied. Holm clears the clipboard in {secs} seconds.")?;
        Ok(())
    }

    /// Clears the clipboard if a copy is pending and it still holds Holm's value.
    /// The value is wiped either way.
    fn clear_clipboard(&mut self, err: &mut dyn Write) -> Result<(), CliError> {
        let Some(mut p) = self.pending.take() else {
            return Ok(());
        };
        if !p.clip.holds(&p.value) {
            writeln!(
                err,
                "The clipboard changed since Holm copied to it, so Holm left it alone."
            )?;
            return Ok(());
        }
        p.clip.clear();
        if p.clip.holds(&p.value) {
            writeln!(err, "holm: {}", CliError::ClearFailed)?;
        } else {
            writeln!(err, "Clipboard cleared.")?;
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
        let clear = self.pending.as_ref().map(|p| p.at);
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
    use super::*;

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
