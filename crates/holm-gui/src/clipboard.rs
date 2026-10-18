//! Holm's own clipboard: the only way a secret leaves the window, and the only way
//! pasted text comes in.
//!
//! egui's clipboard is off (eframe's `clipboard` feature and
//! `NativeOptions::clipboard_shortcuts` are both off), so egui never turns Cmd+C, X or V
//! into copy, cut or paste on its own, and the app never calls `ctx.copy_text`. The
//! Copy button calls [`SecretClipboard::set_secret`]; Cmd+V reads
//! [`SecretClipboard::get_text`], straight into a [`SecretInput`] for a secret field
//! ([`paste_into`]) or as an injected `egui::Event::Paste` for a plain field
//! (`HolmApp`'s `raw_input_hook`).
//!
//! The trait is the seam for tests: [`SystemClipboard`] talks to the macOS pasteboard
//! through `arboard`, and tests use a fake. Nothing here logs or formats a clipboard
//! value: `Debug` shows no text and errors carry no library message.

use core::fmt;
use std::borrow::Cow;

use arboard::SetExtApple as _;
use zeroize::Zeroizing;

use crate::secret_input::SecretInput;

/// Why a copy did not happen. No library text is kept: the UI shows fixed lines only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipboardError {
    /// There is no clipboard to talk to (it could not be opened, or this is
    /// [`NoClipboard`]).
    Unavailable,
    /// The clipboard was there but did not take the text.
    Refused,
}

/// Where copied secrets go and pasted text comes from. Lives on the UI thread, so there
/// is no `Send` bound.
pub trait SecretClipboard {
    /// Puts `text` on the clipboard, marked as concealed where the platform allows it,
    /// so clipboard managers are asked not to keep it.
    ///
    /// # Errors
    ///
    /// [`ClipboardError`] when the clipboard is missing or refuses the text.
    fn set_secret(&mut self, text: &str) -> Result<(), ClipboardError>;

    /// The clipboard's text, in a buffer that wipes itself when dropped. `None` when the
    /// clipboard is empty, holds no text, or cannot be read.
    fn get_text(&mut self) -> Option<Zeroizing<String>>;
}

/// The system clipboard (the macOS general pasteboard), through `arboard`. It is opened
/// on first use, not at start-up, and kept open after that.
pub struct SystemClipboard {
    /// The open clipboard, or `None` before first use or after it failed to open.
    inner: Option<arboard::Clipboard>,
}

impl SystemClipboard {
    /// A clipboard that opens on first use.
    #[must_use]
    pub fn new() -> SystemClipboard {
        SystemClipboard { inner: None }
    }

    /// The open clipboard, opening it now if needed. `None` when it cannot be opened;
    /// the library's error is dropped, because its text is never shown.
    fn open(&mut self) -> Option<&mut arboard::Clipboard> {
        if self.inner.is_none() {
            self.inner = arboard::Clipboard::new().ok();
        }
        self.inner.as_mut()
    }
}

impl Default for SystemClipboard {
    fn default() -> SystemClipboard {
        SystemClipboard::new()
    }
}

impl fmt::Debug for SystemClipboard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemClipboard")
            .field("open", &self.inner.is_some())
            .finish()
    }
}

impl SecretClipboard for SystemClipboard {
    fn set_secret(&mut self, text: &str) -> Result<(), ClipboardError> {
        let clipboard = self.open().ok_or(ClipboardError::Unavailable)?;
        // `exclude_from_history` adds `org.nspasteboard.ConcealedType`. `Cow::Borrowed`
        // hands arboard the caller's text without another Rust copy; the pasteboard
        // itself keeps its own, which Holm cannot wipe.
        clipboard
            .set()
            .exclude_from_history()
            .text(Cow::Borrowed(text))
            .map_err(|_| ClipboardError::Refused)
    }

    fn get_text(&mut self) -> Option<Zeroizing<String>> {
        // The `String` moves into `Zeroizing` with no copy in between.
        self.open()?.get().text().ok().map(Zeroizing::new)
    }
}

/// A clipboard that is never there: copies fail with [`ClipboardError::Unavailable`] and
/// pastes find nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoClipboard;

impl SecretClipboard for NoClipboard {
    fn set_secret(&mut self, _text: &str) -> Result<(), ClipboardError> {
        Err(ClipboardError::Unavailable)
    }

    fn get_text(&mut self) -> Option<Zeroizing<String>> {
        None
    }
}

/// What [`paste_into`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Paste {
    /// No text was added: the clipboard held no text, or only control characters.
    Nothing,
    /// The text was added.
    Pasted,
    /// The text would not fit, so none of it was added.
    TooLong,
}

/// Pastes the clipboard's text into `buf`, all of it or nothing.
///
/// Control characters (such as a trailing `\n` or `\r\n`) are skipped, as for typing. If
/// the rest would take `buf` past its capacity, nothing is added and the caller shows a
/// fixed line: a paste is never cut short without the user knowing. The clipboard's
/// copy is wiped when this returns.
pub fn paste_into(clipboard: &mut dyn SecretClipboard, buf: &mut SecretInput) -> Paste {
    let Some(text) = clipboard.get_text() else {
        return Paste::Nothing;
    };
    let before = buf.char_count();
    if !buf.try_push_str(&text) {
        return Paste::TooLong;
    }
    if buf.char_count() == before {
        Paste::Nothing
    } else {
        Paste::Pasted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serves one fixed text and counts reads.
    struct Serving(Option<&'static str>);

    impl SecretClipboard for Serving {
        fn set_secret(&mut self, _text: &str) -> Result<(), ClipboardError> {
            Ok(())
        }

        fn get_text(&mut self) -> Option<Zeroizing<String>> {
            self.0.map(|t| Zeroizing::new(t.to_owned()))
        }
    }

    #[test]
    fn paste_adds_text_without_controls() {
        let mut buf = SecretInput::with_capacity(32);
        assert_eq!(
            paste_into(&mut Serving(Some("EXAMPLE-pasted\r\n")), &mut buf),
            Paste::Pasted
        );
        assert_eq!(buf.char_count(), 14);
    }

    #[test]
    fn paste_over_cap_adds_nothing() {
        let mut buf = SecretInput::with_capacity(8);
        buf.push_str("ab");
        assert_eq!(
            paste_into(&mut Serving(Some("EXAMPLE")), &mut buf),
            Paste::TooLong
        );
        assert_eq!(buf.char_count(), 2, "nothing was cut and added");
        // Exactly filling the buffer is fine; control characters do not count.
        assert_eq!(
            paste_into(&mut Serving(Some("EXAMPL\n")), &mut buf),
            Paste::Pasted
        );
        assert_eq!(buf.char_count(), 8);
    }

    #[test]
    fn empty_or_control_only_paste_is_nothing() {
        let mut buf = SecretInput::with_capacity(8);
        assert_eq!(paste_into(&mut Serving(None), &mut buf), Paste::Nothing);
        assert_eq!(
            paste_into(&mut Serving(Some("\n")), &mut buf),
            Paste::Nothing
        );
        assert_eq!(paste_into(&mut NoClipboard, &mut buf), Paste::Nothing);
        assert!(buf.is_empty());
    }

    #[test]
    fn no_clipboard_refuses_copies() {
        assert_eq!(
            NoClipboard.set_secret("EXAMPLE"),
            Err(ClipboardError::Unavailable)
        );
    }

    #[test]
    fn system_clipboard_opens_lazily_and_debug_shows_no_text() {
        // `new` must not touch the pasteboard, so tests and CI never open it.
        let clipboard = SystemClipboard::new();
        assert!(clipboard.inner.is_none());
        assert_eq!(format!("{clipboard:?}"), "SystemClipboard { open: false }");
    }
}
