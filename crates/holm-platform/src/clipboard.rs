//! The system clipboard for holm-cli's `--copy`: the macOS general pasteboard, through
//! arboard's safe API.
//!
//! Every copy is marked `org.nspasteboard.ConcealedType` (arboard's
//! `exclude_from_history`), which asks clipboard managers not to keep it. Reading the
//! clipboard back is only for [`ConcealedClipboard::holds`]: the text goes straight
//! into a wiping buffer, is compared, and is dropped. Nothing here formats or logs a
//! clipboard value, and errors carry no library message.
//!
//! On every other system [`ConcealedClipboard::open`] returns
//! [`ClipboardError::Unavailable`], so the CLI says it can't copy there.

#![forbid(unsafe_code)]

use core::fmt;

/// Why the clipboard can't be used. No library text is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipboardError {
    /// There is no clipboard to talk to on this system, or it could not be opened.
    Unavailable,
    /// The clipboard was there but did not take the text.
    Refused,
}

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

    use super::{ClipboardError, ConcealedClipboard};

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

        /// True if the clipboard's text is exactly `text`. The text read back moves
        /// into a wiping buffer with no copy, and is dropped after the compare.
        pub fn holds(&mut self, text: &str) -> bool {
            self.inner
                .get()
                .text()
                .ok()
                .map(Zeroizing::new)
                .is_some_and(|now| now.as_str() == text)
        }

        /// Empties the clipboard. A failure is not reported here; callers check
        /// [`ConcealedClipboard::holds`] afterwards.
        pub fn clear(&mut self) {
            let _ = self.inner.clear();
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{ClipboardError, ConcealedClipboard};

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
        pub fn holds(&mut self, _text: &str) -> bool {
            match self.never {}
        }

        /// Never called: no value of this type exists here.
        pub fn clear(&mut self) {
            match self.never {}
        }
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
        assert!(clip.holds("holm-EXAMPLE-clip"));
        assert!(!clip.holds("something else"));
        clip.clear();
        assert!(!clip.holds("holm-EXAMPLE-clip"));
    }
}
