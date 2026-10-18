//! The terminal prompt for holm-cli: one line read from the controlling terminal,
//! with or without echo.
//!
//! Input comes only from `/dev/tty`, never from the process's standard input, so a
//! password can't arrive through a pipe or a redirected file. If the process has no
//! controlling terminal, every function here returns [`TtyError::NoTerminal`].
//!
//! While a prompt is open the terminal is in a raw mode: no echo, no line editing
//! by the kernel, and no signal keys. The small line editor in this module handles
//! Backspace, Ctrl-U, Ctrl-C and Ctrl-D itself, so Ctrl-C arrives as a byte, not as a
//! signal, and the prompt always has the chance to put the terminal back. A guard
//! restores the saved mode when it drops: on a normal return, on an error, and while
//! a panic unwinds. A process killed from outside (for example `kill -9`, or a
//! `SIGINT` sent by another program) never runs the guard, so the terminal keeps
//! echo off until `stty sane` or a new terminal (`docs/CRYPTO.md`).
//!
//! The typed bytes go into a buffer allocated once, at the caller's limit, and wiped
//! on every exit path. Nothing here formats the input or puts it in an error.
//!
//! Unix only. On other systems every function returns [`TtyError::Unsupported`].

#![forbid(unsafe_code)]

use std::io::{ErrorKind, Write};
use std::time::Instant;

use zeroize::{Zeroize, Zeroizing};

/// Why a terminal read gave no line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TtyError {
    /// There is no controlling terminal (`/dev/tty` could not be opened, or it is not
    /// a terminal).
    NoTerminal,
    /// The user pressed Ctrl-C, or Ctrl-D on an empty line, or the terminal closed.
    Cancelled,
    /// The input was longer than the limit. Nothing typed is kept.
    TooLong,
    /// The input was not valid UTF-8. Nothing typed is kept.
    NotUtf8,
    /// This system has no terminal support in Holm.
    Unsupported,
    /// Any other terminal error, by its kind.
    Io(ErrorKind),
}

/// How [`read_line`] reads one line.
#[derive(Clone, Copy, Debug)]
pub struct LineOpts {
    /// Show what is typed. Off for passwords.
    pub echo: bool,
    /// The most bytes the line may hold. One more byte is [`TtyError::TooLong`].
    pub max_bytes: usize,
    /// Give up at this time and return `Ok(None)`. `None` waits for ever.
    pub deadline: Option<Instant>,
}

/// How [`edit`] stopped without an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    all(not(unix), not(test)),
    expect(dead_code, reason = "the editor runs only on Unix terminals")
)]
pub(crate) enum EditEnd {
    /// Enter (CR or LF) ended the line.
    Enter,
    /// The input ran out before Enter.
    Eof,
}

/// The state of an escape sequence the editor is skipping.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    all(not(unix), not(test)),
    expect(dead_code, reason = "the editor runs only on Unix terminals")
)]
enum Escape {
    /// Not in a sequence.
    None,
    /// After ESC.
    Start,
    /// After `ESC [` (CSI): parameter and intermediate bytes until a final byte.
    Csi,
    /// After `ESC O` (SS3): one more byte ends it.
    Ss3,
}

/// The line editor. Reads `bytes` into `buf` until Enter, the end of the input or an
/// error, and echoes accepted bytes to `echo_out` only when `opts.echo` is on.
///
/// - CR or LF ends the line ([`EditEnd::Enter`]).
/// - DEL or BS removes the last character (every byte of it).
/// - Ctrl-U clears the line.
/// - Ctrl-C, or Ctrl-D on an empty line, is [`TtyError::Cancelled`]. Ctrl-D on a line
///   with text is ignored.
/// - An escape sequence (arrow keys and the like) is skipped. Every other control
///   byte is ignored.
/// - A byte past `opts.max_bytes`, or past the buffer's capacity, is
///   [`TtyError::TooLong`], so the buffer never reallocates (a reallocation would
///   leave a copy of the input in freed memory).
///
/// Every error wipes `buf`. Removed bytes are zeroed before the length shrinks.
#[cfg_attr(
    all(not(unix), not(test)),
    expect(dead_code, reason = "the editor runs only on Unix terminals")
)]
pub(crate) fn edit(
    bytes: &mut dyn Iterator<Item = u8>,
    buf: &mut Zeroizing<Vec<u8>>,
    opts: &LineOpts,
    echo_out: &mut dyn Write,
) -> Result<EditEnd, TtyError> {
    let limit = opts.max_bytes.min(buf.capacity());
    let mut escape = Escape::None;
    for byte in bytes {
        match escape {
            Escape::None => {}
            Escape::Start => {
                escape = match byte {
                    b'[' => Escape::Csi,
                    b'O' => Escape::Ss3,
                    _ => Escape::None,
                };
                // ESC then a printable key (Alt+key) drops both; ESC then a control
                // byte drops only the ESC, and the byte is handled below.
                if byte >= 0x20 {
                    continue;
                }
            }
            Escape::Csi => match byte {
                0x20..=0x3f => continue,
                0x40..=0x7e => {
                    escape = Escape::None;
                    continue;
                }
                // Not part of a CSI sequence: stop skipping and handle it.
                _ => escape = Escape::None,
            },
            Escape::Ss3 => {
                escape = Escape::None;
                if byte >= 0x20 {
                    continue;
                }
            }
        }
        match byte {
            b'\r' | b'\n' => return Ok(EditEnd::Enter),
            0x7f | 0x08 => {
                if erase_last_char(buf) && opts.echo {
                    echo(echo_out, b"\x08 \x08", buf)?;
                }
            }
            0x15 => {
                let chars = char_count(buf);
                buf.zeroize();
                if opts.echo {
                    for _ in 0..chars {
                        echo(echo_out, b"\x08 \x08", buf)?;
                    }
                }
            }
            0x03 => {
                buf.zeroize();
                return Err(TtyError::Cancelled);
            }
            0x04 => {
                if buf.is_empty() {
                    return Err(TtyError::Cancelled);
                }
            }
            0x1b => escape = Escape::Start,
            0x00..=0x1f => {}
            _ => {
                if buf.len() >= limit {
                    buf.zeroize();
                    return Err(TtyError::TooLong);
                }
                buf.push(byte);
                if opts.echo {
                    echo(echo_out, &[byte], buf)?;
                }
            }
        }
    }
    Ok(EditEnd::Eof)
}

/// Writes `what` to `out`; on failure wipes `buf` and returns the error's kind.
fn echo(out: &mut dyn Write, what: &[u8], buf: &mut Zeroizing<Vec<u8>>) -> Result<(), TtyError> {
    out.write_all(what).and_then(|()| out.flush()).map_err(|e| {
        buf.zeroize();
        TtyError::Io(e.kind())
    })
}

/// Removes the last UTF-8 character (its continuation bytes and its lead byte),
/// zeroing them first. Returns false if `buf` was empty.
fn erase_last_char(buf: &mut Zeroizing<Vec<u8>>) -> bool {
    let Some(mut start) = buf.len().checked_sub(1) else {
        return false;
    };
    while start > 0 && is_continuation(buf[start]) {
        start -= 1;
    }
    buf[start..].zeroize();
    buf.truncate(start);
    true
}

/// The number of characters (lead bytes) in `buf`, for erasing the echo.
fn char_count(buf: &[u8]) -> usize {
    buf.iter().filter(|b| !is_continuation(**b)).count()
}

/// True for a UTF-8 continuation byte (`10xxxxxx`).
fn is_continuation(byte: u8) -> bool {
    byte & 0xc0 == 0x80
}

/// Reads one line from the terminal after writing `prompt` to it.
///
/// Returns `Ok(Some(line))` when Enter ends the line, and `Ok(None)` when
/// `opts.deadline` passes first. The line is checked for UTF-8 after Enter.
///
/// # Errors
/// [`TtyError::NoTerminal`] without a controlling terminal; [`TtyError::Cancelled`]
/// for Ctrl-C, Ctrl-D on an empty line, or a closed terminal; [`TtyError::TooLong`];
/// [`TtyError::NotUtf8`]; [`TtyError::Io`] for any other terminal error; and
/// [`TtyError::Unsupported`] off Unix.
pub fn read_line(prompt: &str, opts: LineOpts) -> Result<Option<Zeroizing<String>>, TtyError> {
    #[cfg(unix)]
    {
        unix::read_line(prompt, opts)
    }
    #[cfg(not(unix))]
    {
        let _ = (prompt, opts);
        Err(TtyError::Unsupported)
    }
}

/// Waits until `until` for Enter or Ctrl-C on the terminal. Returns true if one of
/// them came first, false if the time ran out. Other keys are read and dropped.
///
/// # Errors
/// [`TtyError::NoTerminal`], [`TtyError::Io`], or [`TtyError::Unsupported`] off Unix.
pub fn wait_for_key(until: Instant) -> Result<bool, TtyError> {
    #[cfg(unix)]
    {
        unix::wait_for_key(until)
    }
    #[cfg(not(unix))]
    {
        let _ = until;
        Err(TtyError::Unsupported)
    }
}

#[cfg(unix)]
mod unix {
    //! The `/dev/tty` side: open, raw mode with a restoring guard, byte reads.

    use std::fs::{File, OpenOptions};
    use std::io::{ErrorKind, Read, Write};
    use std::mem;
    use std::time::Instant;

    use rustix::io::Errno;
    use rustix::termios::{
        LocalModes, OptionalActions, QueueSelector, SpecialCodeIndex, Termios, tcflush, tcgetattr,
        tcsetattr,
    };
    use zeroize::{Zeroize, Zeroizing};

    use super::{EditEnd, LineOpts, TtyError, edit};

    /// The controlling terminal's device.
    const TTY_PATH: &str = "/dev/tty";

    /// Puts the saved terminal mode back when it drops, after discarding unread input
    /// if `flush_input` is set.
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

    /// Opens the controlling terminal for reading and writing.
    fn open_tty() -> Result<File, TtyError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(TTY_PATH)
            .map_err(|_| TtyError::NoTerminal)
    }

    fn errno(e: Errno) -> TtyError {
        if e == Errno::NOTTY {
            TtyError::NoTerminal
        } else {
            TtyError::Io(std::io::Error::from(e).kind())
        }
    }

    fn io_kind(e: &std::io::Error) -> TtyError {
        TtyError::Io(e.kind())
    }

    /// Saves the mode, installs the guard, then switches to raw mode: no echo, no
    /// canonical line editing, no signal keys, no extended input processing. With a
    /// deadline, reads wake every 0.1 s (`VMIN = 0`, `VTIME = 1`) so the deadline is
    /// checked; without one, a read blocks for a byte (`VMIN = 1`, `VTIME = 0`), so a
    /// read of zero bytes means the terminal closed.
    fn raw_mode(tty: &File, polling: bool) -> Result<ModeGuard<'_>, TtyError> {
        let saved = tcgetattr(tty).map_err(errno)?;
        let mut raw = saved.clone();
        let guard = ModeGuard {
            tty,
            saved,
            flush_input: false,
        };
        raw.local_modes.remove(
            LocalModes::ECHO
                | LocalModes::ECHONL
                | LocalModes::ICANON
                | LocalModes::ISIG
                | LocalModes::IEXTEN,
        );
        let (vmin, vtime) = if polling { (0, 1) } else { (1, 0) };
        raw.special_codes[SpecialCodeIndex::VMIN] = vmin;
        raw.special_codes[SpecialCodeIndex::VTIME] = vtime;
        tcsetattr(tty, OptionalActions::Now, &raw).map_err(errno)?;
        Ok(guard)
    }

    /// Why [`TtyBytes`] stopped yielding bytes.
    #[derive(Clone, Copy)]
    enum Stop {
        Closed,
        Deadline,
        Io(ErrorKind),
    }

    /// The terminal's input as an iterator of bytes, one `read` per byte.
    struct TtyBytes<'a> {
        tty: &'a File,
        deadline: Option<Instant>,
        stop: Option<Stop>,
    }

    impl Iterator for TtyBytes<'_> {
        type Item = u8;

        fn next(&mut self) -> Option<u8> {
            if self.stop.is_some() {
                return None;
            }
            loop {
                if let Some(deadline) = self.deadline
                    && Instant::now() >= deadline
                {
                    self.stop = Some(Stop::Deadline);
                    return None;
                }
                let mut one = [0_u8; 1];
                let mut reader = self.tty;
                match reader.read(&mut one) {
                    Ok(1) => {
                        let byte = one[0];
                        one.zeroize();
                        return Some(byte);
                    }
                    // A poll that timed out: check the deadline again.
                    Ok(_) if self.deadline.is_some() => {}
                    Ok(_) => {
                        self.stop = Some(Stop::Closed);
                        return None;
                    }
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => {
                        self.stop = Some(Stop::Io(e.kind()));
                        return None;
                    }
                }
            }
        }
    }

    pub(super) fn read_line(
        prompt: &str,
        opts: LineOpts,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        let tty = open_tty()?;
        let mut guard = raw_mode(&tty, opts.deadline.is_some())?;
        let mut out = &tty;
        out.write_all(prompt.as_bytes())
            .and_then(|()| out.flush())
            .map_err(|e| io_kind(&e))?;

        let mut buf = Zeroizing::new(Vec::with_capacity(opts.max_bytes));
        let mut bytes = TtyBytes {
            tty: &tty,
            deadline: opts.deadline,
            stop: None,
        };
        let ended = edit(&mut bytes, &mut buf, &opts, &mut out);
        // The cursor is still on the prompt line; move it down. A failure here does not
        // change the result.
        let _ = out.write_all(b"\n");
        match ended {
            Ok(EditEnd::Enter) => {}
            Ok(EditEnd::Eof) => {
                buf.zeroize();
                return match bytes.stop {
                    Some(Stop::Deadline) => Ok(None),
                    Some(Stop::Io(kind)) => Err(TtyError::Io(kind)),
                    Some(Stop::Closed) | None => Err(TtyError::Cancelled),
                };
            }
            Err(e) => {
                if matches!(e, TtyError::TooLong | TtyError::Cancelled) {
                    guard.flush_input = true;
                }
                return Err(e);
            }
        }
        drop(guard);
        // Move the bytes out without a copy; `buf` keeps an empty vector.
        match String::from_utf8(mem::take(&mut *buf)) {
            Ok(line) => Ok(Some(Zeroizing::new(line))),
            Err(e) => {
                let mut bytes = e.into_bytes();
                bytes.zeroize();
                Err(TtyError::NotUtf8)
            }
        }
    }

    pub(super) fn wait_for_key(until: Instant) -> Result<bool, TtyError> {
        let tty = open_tty()?;
        let _guard = raw_mode(&tty, true)?;
        let mut bytes = TtyBytes {
            tty: &tty,
            deadline: Some(until),
            stop: None,
        };
        let pressed = bytes.any(|b| matches!(b, b'\r' | b'\n' | 0x03));
        if let Some(Stop::Io(kind)) = bytes.stop {
            return Err(TtyError::Io(kind));
        }
        Ok(pressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(echo: bool, max_bytes: usize) -> LineOpts {
        LineOpts {
            echo,
            max_bytes,
            deadline: None,
        }
    }

    /// Runs the editor over `input` with echo off and a 64-byte limit.
    fn run(input: &[u8]) -> (Result<EditEnd, TtyError>, Vec<u8>) {
        let mut buf = Zeroizing::new(Vec::with_capacity(64));
        let mut out = Vec::new();
        let end = edit(
            &mut input.iter().copied(),
            &mut buf,
            &opts(false, 64),
            &mut out,
        );
        (end, buf.to_vec())
    }

    #[test]
    fn editor_handles_backspace_ctrl_u_ctrl_c() {
        assert_eq!(run(b"ab\x7fc\r"), (Ok(EditEnd::Enter), b"ac".to_vec()));
        assert_eq!(run(b"ab\x08c\n"), (Ok(EditEnd::Enter), b"ac".to_vec()));
        assert_eq!(run(b"xy\x15z\r"), (Ok(EditEnd::Enter), b"z".to_vec()));
        assert_eq!(run(b"a\x03"), (Err(TtyError::Cancelled), Vec::new()));
        assert_eq!(run(b"\x04"), (Err(TtyError::Cancelled), Vec::new()));
        // Ctrl-D with text on the line does nothing.
        assert_eq!(run(b"a\x04b\r"), (Ok(EditEnd::Enter), b"ab".to_vec()));
        // One DEL removes both bytes of "é".
        assert_eq!(
            run("a\u{e9}\x7f\r".as_bytes()),
            (Ok(EditEnd::Enter), b"a".to_vec())
        );
        // DEL on an empty line does nothing.
        assert_eq!(run(b"\x7fa\r"), (Ok(EditEnd::Enter), b"a".to_vec()));
        // Other control bytes are ignored, and arrow keys are skipped whole.
        assert_eq!(
            run(b"a\x01\x09\x00b\x1b[Dc\x1bOAd\x1b[1;5Ce\r"),
            (Ok(EditEnd::Enter), b"abcde".to_vec())
        );
        // Enter inside an unfinished escape sequence still ends the line.
        assert_eq!(run(b"a\x1b[\r"), (Ok(EditEnd::Enter), b"a".to_vec()));
        // The input ran out before Enter.
        assert_eq!(run(b"ab"), (Ok(EditEnd::Eof), b"ab".to_vec()));
    }

    #[test]
    fn editor_never_echoes_when_echo_off() {
        let mut buf = Zeroizing::new(Vec::with_capacity(64));
        let mut out = Vec::new();
        let input = b"secret\x7f\x15abc\r";
        let end = edit(
            &mut input.iter().copied(),
            &mut buf,
            &opts(false, 64),
            &mut out,
        );
        assert_eq!(end, Ok(EditEnd::Enter));
        assert!(out.is_empty());

        // With echo on, typed bytes are shown and erased ones are rubbed out.
        let mut buf = Zeroizing::new(Vec::with_capacity(64));
        let mut out = Vec::new();
        let end = edit(
            &mut b"ab\x7f\r".iter().copied(),
            &mut buf,
            &opts(true, 64),
            &mut out,
        );
        assert_eq!(end, Ok(EditEnd::Enter));
        assert_eq!(out, b"ab\x08 \x08");
    }

    #[test]
    fn editor_refuses_past_max() {
        let mut buf = Zeroizing::new(Vec::with_capacity(64));
        let mut out = Vec::new();
        let end = edit(
            &mut b"abcde\r".iter().copied(),
            &mut buf,
            &opts(false, 4),
            &mut out,
        );
        assert_eq!(end, Err(TtyError::TooLong));
        assert!(buf.is_empty());

        // Exactly at the limit is fine.
        let mut buf = Zeroizing::new(Vec::with_capacity(64));
        let end = edit(
            &mut b"abcd\r".iter().copied(),
            &mut buf,
            &opts(false, 4),
            &mut out,
        );
        assert_eq!(end, Ok(EditEnd::Enter));
        assert_eq!(&buf[..], b"abcd");
    }

    #[test]
    fn editor_buffer_never_grows() {
        let mut buf = Zeroizing::new(Vec::with_capacity(1024));
        let (cap, ptr) = (buf.capacity(), buf.as_ptr());
        let input = vec![b'a'; 1024];
        let mut out = Vec::new();
        let end = edit(
            &mut input.iter().copied(),
            &mut buf,
            &opts(false, 4096),
            &mut out,
        );
        assert_eq!(end, Ok(EditEnd::Eof));
        assert_eq!(buf.len(), 1024);
        assert_eq!((buf.capacity(), buf.as_ptr()), (cap, ptr));

        // One byte more than the buffer holds is refused, not a reallocation.
        let end = edit(
            &mut b"b".iter().copied(),
            &mut buf,
            &opts(false, 4096),
            &mut out,
        );
        assert_eq!(end, Err(TtyError::TooLong));
        assert_eq!((buf.capacity(), buf.as_ptr()), (cap, ptr));
    }

    /// Run by hand in a terminal: `cargo test -p holm-platform --features tty
    /// manual_prompt -- --ignored --nocapture`, then type `abc`, a Backspace, `c` and
    /// Enter. Nothing should echo, and the terminal should echo again afterwards.
    #[test]
    #[ignore = "needs a person at a real terminal"]
    fn manual_prompt_on_a_real_tty() {
        let line = read_line("Type abc, Backspace, c, Enter (no echo): ", opts(false, 64))
            .unwrap()
            .unwrap();
        assert_eq!(line.as_str(), "abc");
    }
}
