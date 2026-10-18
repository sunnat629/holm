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
//! through holm-platform's concealed clipboard, and tests use a fake. Nothing here logs or formats a clipboard
//! value: `Debug` shows no text and errors carry no library message.

use core::fmt;

pub use holm_platform::clip_clear::{Clip, ClipCheck, ClipboardError};
use holm_platform::clipboard::ConcealedClipboard;
use zeroize::Zeroizing;

use crate::secret_input::SecretInput;

/// Where copied secrets go and pasted text comes from. It is a [`Clip`] (set, check
/// and clear, shared with the CLI), so the app can clear what it copied. Lives on the
/// UI thread, so there is no `Send` bound.
pub trait SecretClipboard: Clip {
    /// The clipboard's text, in a buffer that wipes itself when dropped. `None` when the
    /// clipboard is empty, holds no text, or cannot be read.
    fn get_text(&mut self) -> Option<Zeroizing<String>>;
}

/// The system clipboard (the macOS general pasteboard), through holm-platform's
/// concealed clipboard. It is opened on first use, not at start-up, and kept open after
/// that.
pub struct SystemClipboard {
    /// The open clipboard, or `None` before first use or after it failed to open.
    inner: Option<ConcealedClipboard>,
}

impl SystemClipboard {
    /// A clipboard that opens on first use.
    #[must_use]
    pub fn new() -> SystemClipboard {
        SystemClipboard { inner: None }
    }

    /// The open clipboard, opening it now if needed. `None` when it cannot be opened;
    /// the library's error is dropped, because its text is never shown.
    fn open(&mut self) -> Option<&mut ConcealedClipboard> {
        if self.inner.is_none() {
            self.inner = ConcealedClipboard::open().ok();
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

impl Clip for SystemClipboard {
    fn set(&mut self, text: &str) -> Result<(), ClipboardError> {
        self.open().ok_or(ClipboardError::Unavailable)?.set(text)
    }

    fn check(&mut self, text: &str) -> ClipCheck {
        self.open().map_or(ClipCheck::Unreadable, |c| c.check(text))
    }

    fn clear(&mut self) {
        if let Some(c) = self.open() {
            c.clear();
        }
    }
}

impl SecretClipboard for SystemClipboard {
    fn get_text(&mut self) -> Option<Zeroizing<String>> {
        self.open()?.get_text()
    }
}

/// A clipboard that is never there: copies fail with [`ClipboardError::Unavailable`],
/// pastes find nothing and a check is unreadable.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoClipboard;

impl Clip for NoClipboard {
    fn set(&mut self, _text: &str) -> Result<(), ClipboardError> {
        Err(ClipboardError::Unavailable)
    }

    fn check(&mut self, _text: &str) -> ClipCheck {
        ClipCheck::Unreadable
    }

    fn clear(&mut self) {}
}

impl SecretClipboard for NoClipboard {
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

    impl Clip for Serving {
        fn set(&mut self, _text: &str) -> Result<(), ClipboardError> {
            Ok(())
        }

        fn check(&mut self, _text: &str) -> ClipCheck {
            ClipCheck::Other
        }

        fn clear(&mut self) {}
    }

    impl SecretClipboard for Serving {
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
        assert_eq!(NoClipboard.set("EXAMPLE"), Err(ClipboardError::Unavailable));
        assert_eq!(NoClipboard.check("EXAMPLE"), ClipCheck::Unreadable);
    }

    #[test]
    fn system_clipboard_opens_lazily_and_debug_shows_no_text() {
        // `new` must not touch the pasteboard, so tests and CI never open it.
        let clipboard = SystemClipboard::new();
        assert!(clipboard.inner.is_none());
        assert_eq!(format!("{clipboard:?}"), "SystemClipboard { open: false }");
    }
}
