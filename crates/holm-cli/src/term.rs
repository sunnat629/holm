//! The terminal as a trait, so tests swap in a fake one.
//!
//! [`RealTerminal`] reads from the controlling terminal through
//! `holm_platform::tty`. Tests use a fake that answers from a queue. Every command
//! asks for input only through [`Terminal`], so no command can read a password from
//! anywhere else.
//!
//! The `*_interruptible` methods take an [`Interrupt`] for one call: a check the
//! terminal makes about every 0.1 s while it waits. `holm shell` uses it to stop a
//! prompt and lock when the computer has slept. It is passed per call, not stored, so
//! the terminal never keeps a closure that reaches into the shell.

use std::time::Instant;

use holm_platform::tty::{self, LineOpts, TtyError};
use zeroize::Zeroizing;

/// A check made while a prompt waits; when it returns true the prompt stops, wipes
/// what was typed and answers `Ok(None)` (or false for a wait). `None` never stops.
pub type Interrupt<'a> = Option<&'a dyn Fn() -> bool>;

/// Where Holm asks the user for input.
pub trait Terminal {
    /// Asks for a secret with no echo, waiting as long as it takes.
    ///
    /// # Errors
    /// [`TtyError`]; Ctrl-C is [`TtyError::Cancelled`], and Ctrl-D on an empty line
    /// or a closed terminal is [`TtyError::EndOfInput`].
    fn secret(&mut self, prompt: &str, max_bytes: usize) -> Result<Zeroizing<String>, TtyError>;

    /// Asks for a secret with no echo. `Ok(None)` means `deadline` passed first.
    ///
    /// The default ignores the deadline and waits, so a terminal that can't time out
    /// still works.
    ///
    /// # Errors
    /// As [`Terminal::secret`].
    fn secret_until(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        let _ = deadline;
        self.secret(prompt, max_bytes).map(Some)
    }

    /// Asks for a visible line. `Ok(None)` means `deadline` passed first.
    ///
    /// # Errors
    /// [`TtyError`].
    fn line(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, TtyError>;

    /// Waits until `until` for Enter or Ctrl-C; true if one came first.
    ///
    /// # Errors
    /// [`TtyError`].
    fn wait_for_key(&mut self, until: Instant) -> Result<bool, TtyError>;

    /// [`Terminal::secret_until`] that also stops when `interrupt` returns true.
    ///
    /// The default ignores the interrupt, so a terminal that can't poll still works.
    ///
    /// # Errors
    /// As [`Terminal::secret`].
    fn secret_interruptible(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
        interrupt: Interrupt<'_>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        let _ = interrupt;
        self.secret_until(prompt, max_bytes, deadline)
    }

    /// [`Terminal::line`] that also stops when `interrupt` returns true.
    ///
    /// The default ignores the interrupt.
    ///
    /// # Errors
    /// [`TtyError`].
    fn line_interruptible(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
        interrupt: Interrupt<'_>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        let _ = interrupt;
        self.line(prompt, max_bytes, deadline)
    }

    /// [`Terminal::wait_for_key`] that also stops, answering false, when `interrupt`
    /// returns true.
    ///
    /// The default ignores the interrupt.
    ///
    /// # Errors
    /// [`TtyError`].
    fn wait_for_key_interruptible(
        &mut self,
        until: Instant,
        interrupt: Interrupt<'_>,
    ) -> Result<bool, TtyError> {
        let _ = interrupt;
        self.wait_for_key(until)
    }
}

/// The controlling terminal (`/dev/tty`).
#[derive(Clone, Copy, Debug, Default)]
pub struct RealTerminal;

impl Terminal for RealTerminal {
    fn secret(&mut self, prompt: &str, max_bytes: usize) -> Result<Zeroizing<String>, TtyError> {
        let opts = LineOpts {
            echo: false,
            max_bytes,
            deadline: None,
            interrupt: None,
        };
        // With no deadline a line always comes back; `None` cannot happen, but it is
        // handled as a cancel rather than a panic.
        tty::read_line(prompt, opts)?.ok_or(TtyError::Cancelled)
    }

    fn secret_until(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        self.secret_interruptible(prompt, max_bytes, deadline, None)
    }

    fn line(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        self.line_interruptible(prompt, max_bytes, deadline, None)
    }

    fn wait_for_key(&mut self, until: Instant) -> Result<bool, TtyError> {
        tty::wait_for_key(until, None)
    }

    fn secret_interruptible(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
        interrupt: Interrupt<'_>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        let opts = LineOpts {
            echo: false,
            max_bytes,
            deadline,
            interrupt,
        };
        tty::read_line(prompt, opts)
    }

    fn line_interruptible(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
        interrupt: Interrupt<'_>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        let opts = LineOpts {
            echo: true,
            max_bytes,
            deadline,
            interrupt,
        };
        tty::read_line(prompt, opts)
    }

    fn wait_for_key_interruptible(
        &mut self,
        until: Instant,
        interrupt: Interrupt<'_>,
    ) -> Result<bool, TtyError> {
        tty::wait_for_key(until, interrupt)
    }
}
