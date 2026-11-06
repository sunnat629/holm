//! The system clipboard for holm-cli's `--copy`: the macOS general pasteboard, through
//! arboard's safe API.
//!
//! Every copy is marked `org.nspasteboard.ConcealedType` (arboard's
//! `exclude_from_history`), which asks clipboard managers not to keep it. Reading the
//! clipboard back is only for [`ConcealedClipboard::check`]: the text goes straight
//! into a wiping buffer, is compared, and is dropped. Nothing here formats or logs a
//! clipboard value, and errors carry no library message.
//!
//! On every other system [`ConcealedClipboard::open`] returns
//! [`ClipboardError::Unavailable`], so the CLI says it can't copy there.

#![forbid(unsafe_code)]

use core::fmt;

use crate::clip_clear::Clip;

pub use crate::clip_clear::{ClipCheck, ClipboardError};

/// The open system clipboard.
pub struct ConcealedClipboard {
    #[cfg(target_os = "macos")]
    inner: arboard::Clipboard,
    /// Never built outside macOS: `open` refuses there.
    #[cfg(not(target_os = "macos"))]
    never: core::convert::Infallible,
}

impl fmt::Debug for ConcealedClipboard {
    // Hand-written: there is nothing to show, and never any text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConcealedClipboard")
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::borrow::Cow;

    use arboard::SetExtApple as _;
    use zeroize::Zeroizing;

    use super::{ClipCheck, ClipboardError, ConcealedClipboard};

    impl ConcealedClipboard {
        /// Opens the system clipboard.
        ///
        /// # Errors
        /// [`ClipboardError::Unavailable`] if it can't be opened.
        pub fn open() -> Result<ConcealedClipboard, ClipboardError> {
            let inner = arboard::Clipboard::new().map_err(|_| ClipboardError::Unavailable)?;
            Ok(ConcealedClipboard { inner })
        }

        /// Puts `text` on the clipboard, marked concealed.
        ///
        /// # Errors
        /// [`ClipboardError::Refused`] if the clipboard did not take it.
        pub fn set(&mut self, text: &str) -> Result<(), ClipboardError> {
            // `Cow::Borrowed` hands arboard the caller's text without another Rust
            // copy; the pasteboard keeps its own, which Holm cannot wipe.
            self.inner
                .set()
                .exclude_from_history()
                .text(Cow::Borrowed(text))
                .map_err(|_| ClipboardError::Refused)
        }

        /// Whether the clipboard's text is exactly `text`. The text read back moves
        /// into a wiping buffer with no copy, and is dropped after the compare. No
        /// text on the clipboard (empty, or an image) is [`ClipCheck::Other`]; any
        /// other read error is [`ClipCheck::Unreadable`], never a guess.
        pub fn check(&mut self, text: &str) -> ClipCheck {
            match self.inner.get().text().map(Zeroizing::new) {
                Ok(now) if now.as_str() == text => ClipCheck::Holds,
                Ok(_) | Err(arboard::Error::ContentNotAvailable) => ClipCheck::Other,
                Err(_) => ClipCheck::Unreadable,
            }
        }

        /// The clipboard's text, in a buffer that wipes itself when dropped. `None`
        /// when it is empty, holds no text, or cannot be read. The `String` moves
        /// into the buffer with no copy in between.
        pub fn get_text(&mut self) -> Option<Zeroizing<String>> {
            self.inner.get().text().ok().map(Zeroizing::new)
        }

        /// Empties the clipboard. A failure is not reported here; callers check
        /// [`ConcealedClipboard::check`] afterwards.
        pub fn clear(&mut self) {
            let _ = self.inner.clear();
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use zeroize::Zeroizing;

    use super::{ClipCheck, ClipboardError, ConcealedClipboard};

    impl ConcealedClipboard {
        /// There is no supported clipboard on this system.
        ///
        /// # Errors
        /// Always [`ClipboardError::Unavailable`].
        pub fn open() -> Result<ConcealedClipboard, ClipboardError> {
            Err(ClipboardError::Unavailable)
        }

        /// Never called: no value of this type exists here.
        ///
        /// # Errors
        /// Always [`ClipboardError::Unavailable`].
        pub fn set(&mut self, _text: &str) -> Result<(), ClipboardError> {
            match self.never {}
        }

        /// Never called: no value of this type exists here.
        pub fn check(&mut self, _text: &str) -> ClipCheck {
            match self.never {}
        }

        /// Never called: no value of this type exists here.
        pub fn get_text(&mut self) -> Option<Zeroizing<String>> {
            match self.never {}
        }

        /// Never called: no value of this type exists here.
        pub fn clear(&mut self) {
            match self.never {}
        }
    }
}

impl Clip for ConcealedClipboard {
    fn set(&mut self, text: &str) -> Result<(), ClipboardError> {
        ConcealedClipboard::set(self, text)
    }

    fn check(&mut self, text: &str) -> ClipCheck {
        ConcealedClipboard::check(self, text)
    }

    fn clear(&mut self) {
        ConcealedClipboard::clear(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_and_debug_hold_no_text() {
        assert_eq!(format!("{:?}", ClipboardError::Unavailable), "Unavailable");
        assert_eq!(format!("{:?}", ClipboardError::Refused), "Refused");
        if let Ok(clip) = ConcealedClipboard::open() {
            assert_eq!(format!("{clip:?}"), "ConcealedClipboard");
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unavailable_off_macos() {
        assert_eq!(
            ConcealedClipboard::open().map(|_| ()),
            Err(ClipboardError::Unavailable)
        );
    }

    /// Run by hand on a Mac: `cargo test -p holm-platform --features clipboard
    /// real_round_trip -- --ignored`. It replaces what is on the clipboard.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "uses the real clipboard"]
    fn real_round_trip() {
        let mut clip = ConcealedClipboard::open().unwrap();
        clip.set("holm-EXAMPLE-clip").unwrap();
        assert_eq!(clip.check("holm-EXAMPLE-clip"), ClipCheck::Holds);
        assert_eq!(clip.check("something else"), ClipCheck::Other);
        clip.clear();
        assert_eq!(clip.check("holm-EXAMPLE-clip"), ClipCheck::Other);
    }
}
