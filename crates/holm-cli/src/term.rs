//! The terminal as a trait, so tests swap in a fake one.
//!
//! [`RealTerminal`] reads from the controlling terminal through
//! `holm_platform::tty`. Tests use a fake that answers from a queue. Every command
//! asks for input only through [`Terminal`], so no command can read a password from
//! anywhere else.

use std::time::Instant;

use holm_platform::tty::{self, LineOpts, TtyError};
use zeroize::Zeroizing;

/// Where Holm asks the user for input.
pub trait Terminal {
    /// Asks for a secret with no echo, waiting as long as it takes.
    ///
    /// # Errors
    /// [`TtyError`]; a closed terminal is [`TtyError::Cancelled`].
    fn secret(&mut self, prompt: &str, max_bytes: usize) -> Result<Zeroizing<String>, TtyError>;

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
        };
        // With no deadline a line always comes back; `None` cannot happen, but it is
        // handled as a cancel rather than a panic.
        tty::read_line(prompt, opts)?.ok_or(TtyError::Cancelled)
    }

    fn line(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        let opts = LineOpts {
            echo: true,
            max_bytes,
            deadline,
        };
        tty::read_line(prompt, opts)
    }

    fn wait_for_key(&mut self, until: Instant) -> Result<bool, TtyError> {
        tty::wait_for_key(until)
    }
}
