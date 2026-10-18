//! A pre-allocated, wiping buffer for a secret being typed.
//!
//! [`SecretInput`] is what the secret field widget (`widgets::secret_field`) types
//! into. It reserves its whole capacity once and never grows, so no reallocation leaves
//! an unwiped copy of the secret behind in freed memory. Every path that removes bytes
//! wipes them first, and the buffer is wiped when dropped. Moving the secret out
//! ([`SecretInput::take_master_password`], [`SecretInput::take_secret_text`]) hands over
//! the allocation itself, with no copy.
//!
//! Only [`SecretInput::push_str`] (one whole UTF-8 character at a time) and
//! [`SecretInput::from_secret`] (a whole `&str`) write bytes, so the contents are always
//! valid UTF-8.

use core::fmt;

use holm_core::text::SecretText;
use holm_crypto::MasterPassword;
use zeroize::{Zeroize, Zeroizing};

/// Capacity in bytes for a master password: [`holm_core::strength::MAX_MASTER_CHARS`]
/// characters of up to four UTF-8 bytes each.
pub const MASTER_CAP: usize = 4 * holm_core::strength::MAX_MASTER_CHARS;

/// Capacity in bytes for an item secret (a login password), the core limit
/// [`holm_core::rules::MAX_SECRET_BYTES`].
pub const ITEM_SECRET_CAP: usize = holm_core::rules::MAX_SECRET_BYTES;

/// A secret being typed: UTF-8 bytes in an allocation that never grows, wiped on
/// [`clear`](SecretInput::clear) and on drop.
///
/// No `Clone`, no `PartialEq` (use [`eq_secret`](SecretInput::eq_secret)), and `Debug`
/// prints only the character count.
pub struct SecretInput {
    /// The secret, always valid UTF-8. `bytes.len() <= cap <= bytes.capacity()`.
    bytes: Vec<u8>,
    /// The most bytes this buffer may hold, fixed when it is made.
    cap: usize,
}

impl SecretInput {
    /// An empty buffer that holds up to `cap` bytes. The memory is reserved here, once.
    #[must_use]
    pub fn with_capacity(cap: usize) -> SecretInput {
        SecretInput {
            bytes: Vec::with_capacity(cap),
            cap,
        }
    }

    /// A buffer of capacity `cap` holding exactly `text`, for editing a stored secret.
    ///
    /// The copy is byte-exact: unlike typed input, nothing is filtered, because a stored
    /// secret may hold characters (such as a tab) that core allows, and saving the edit
    /// must not change it. Returns `None`, and allocates nothing, when `text` is longer
    /// than `cap` bytes; it never truncates.
    #[must_use]
    pub fn from_secret(text: &str, cap: usize) -> Option<SecretInput> {
        if text.len() > cap {
            return None;
        }
        let mut buf = SecretInput::with_capacity(cap);
        buf.bytes.extend_from_slice(text.as_bytes());
        Some(buf)
    }

    /// Appends `s`, one character at a time. Control characters are skipped. It stops at
    /// the first character that would take the buffer past its capacity, so it never
    /// reallocates. Each character passes through a 4-byte scratch that is wiped on every
    /// path, including a panic.
    pub fn push_str(&mut self, s: &str) {
        let mut scratch = Zeroizing::new([0u8; 4]);
        for c in s.chars() {
            if c.is_control() {
                continue;
            }
            let encoded = c.encode_utf8(&mut scratch[..]);
            if encoded.len() > self.cap - self.bytes.len() {
                break;
            }
            self.bytes.extend_from_slice(encoded.as_bytes());
        }
    }

    /// Appends `s` only if all of it fits, and returns whether it did.
    ///
    /// Control characters are skipped, as in [`push_str`](SecretInput::push_str), and do
    /// not count. When the rest would take the buffer past its capacity, nothing is added
    /// and it returns `false`: for a paste, which must never be cut short without the
    /// user knowing.
    #[must_use]
    pub fn try_push_str(&mut self, s: &str) -> bool {
        let needed: usize = s
            .chars()
            .filter(|c| !c.is_control())
            .map(char::len_utf8)
            .sum();
        if needed > self.cap - self.bytes.len() {
            return false;
        }
        self.push_str(s);
        true
    }

    /// Removes the last character, if any, and wipes its bytes.
    pub fn pop_char(&mut self) {
        // UTF-8 continuation bytes look like 0b10xx_xxxx; the character starts at the
        // last byte that is not one.
        let Some(start) = self.bytes.iter().rposition(|b| !is_continuation(*b)) else {
            return;
        };
        self.bytes[start..].zeroize();
        self.bytes.truncate(start);
    }

    /// The number of characters (Unicode scalar values) held.
    #[must_use]
    pub fn char_count(&self) -> usize {
        self.bytes.iter().filter(|b| !is_continuation(**b)).count()
    }

    /// The secret as text, for painting it while the user holds the eye button.
    ///
    /// Borrowed, never copied here. The caller must paint it and drop it in the same
    /// frame, and must not store it.
    #[must_use]
    pub(crate) fn expose_for_paint(&self) -> &str {
        core::str::from_utf8(&self.bytes).unwrap_or("")
    }

    /// True when nothing has been typed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Wipes the whole allocation and empties the buffer. The allocation is kept.
    pub fn clear(&mut self) {
        // `Vec<u8>::zeroize` zeroes every byte of the capacity, then sets the length to 0.
        self.bytes.zeroize();
    }

    /// True when both buffers hold the same secret. Equal lengths are compared without
    /// stopping at the first difference.
    #[must_use]
    pub fn eq_secret(&self, other: &SecretInput) -> bool {
        self.bytes.len() == other.bytes.len()
            && self
                .bytes
                .iter()
                .zip(&other.bytes)
                .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                == 0
    }

    /// A master password holding a copy of the secret; the buffer keeps its contents.
    /// The copy is one allocation of exactly the secret's length, moved into the
    /// [`MasterPassword`] without further copies.
    #[must_use]
    pub fn to_master_password(&self) -> MasterPassword {
        let mut copy = Vec::with_capacity(self.bytes.len());
        copy.extend_from_slice(&self.bytes);
        MasterPassword::new(into_string(copy))
    }

    /// Moves the secret out as a master password, with no copy, and leaves this buffer
    /// empty with a fresh allocation of the same capacity.
    #[must_use]
    pub fn take_master_password(&mut self) -> MasterPassword {
        MasterPassword::new(into_string(self.take_bytes()))
    }

    /// Moves the secret out as item text, with no copy, and leaves this buffer empty
    /// with a fresh allocation of the same capacity.
    #[must_use]
    pub fn take_secret_text(&mut self) -> SecretText {
        SecretText::new(into_string(self.take_bytes()))
    }

    /// Swaps in a fresh allocation and returns the old one, contents and all.
    fn take_bytes(&mut self) -> Vec<u8> {
        std::mem::replace(&mut self.bytes, Vec::with_capacity(self.cap))
    }
}

impl Drop for SecretInput {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretInput(<{} chars hidden>)", self.char_count())
    }
}

/// True for a UTF-8 continuation byte (`0b10xx_xxxx`).
fn is_continuation(byte: u8) -> bool {
    byte & 0b1100_0000 == 0b1000_0000
}

/// Turns `bytes` into a `String` without copying. Only `push_str` and `from_secret` write
/// the bytes, so they are valid UTF-8; if that ever stopped being true, the bytes are wiped and the
/// secret comes back empty rather than panicking.
fn into_string(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(err) => {
            let mut bytes = err.into_bytes();
            bytes.zeroize();
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(SecretInput: Clone, Copy);

    fn filled(text: &str) -> SecretInput {
        let mut buf = SecretInput::with_capacity(MASTER_CAP);
        buf.push_str(text);
        buf
    }

    #[test]
    fn push_pop_utf8() {
        let mut buf = filled("aé€😀");
        assert_eq!(buf.char_count(), 4);
        assert_eq!(buf.bytes, "aé€😀".as_bytes());
        buf.pop_char();
        buf.pop_char();
        assert_eq!(buf.char_count(), 2);
        assert_eq!(buf.bytes, "aé".as_bytes());
        buf.pop_char();
        buf.pop_char();
        assert!(buf.is_empty());
        // Popping an empty buffer is a no-op.
        buf.pop_char();
        assert!(buf.is_empty());
    }

    #[test]
    fn never_reallocates() {
        let cap = 8;
        let mut buf = SecretInput::with_capacity(cap);
        let ptr = buf.bytes.as_ptr();
        let capacity = buf.bytes.capacity();
        assert!(capacity >= cap);
        buf.push_str("abcdefg");
        // "é" is two bytes and would make 9: refused, and so is everything after it.
        buf.push_str("éh");
        assert_eq!(buf.bytes, b"abcdefg");
        buf.push_str("h");
        assert_eq!(buf.bytes, b"abcdefgh");
        buf.push_str("i");
        assert_eq!(buf.bytes.len(), cap);
        assert_eq!(buf.bytes.as_ptr(), ptr);
        assert_eq!(buf.bytes.capacity(), capacity);
    }

    #[test]
    fn try_push_str_is_all_or_nothing() {
        let mut buf = SecretInput::with_capacity(8);
        let ptr = buf.bytes.as_ptr();
        assert!(buf.try_push_str("abc"));
        // "défgh" is 6 bytes and only 5 are left: refused whole, not cut.
        assert!(!buf.try_push_str("défgh"));
        assert_eq!(buf.bytes, b"abc");
        // Control characters do not count toward the fit.
        assert!(buf.try_push_str("de\r\nf\tgh"));
        assert_eq!(buf.bytes, b"abcdefgh");
        assert!(!buf.try_push_str("i"));
        assert!(buf.try_push_str("\n"), "nothing to add always fits");
        assert_eq!(buf.bytes.as_ptr(), ptr, "no reallocation");
    }

    #[test]
    fn controls_skipped() {
        let buf = filled("a\tb\nc\r\u{7f}d\u{0}e\u{85}f");
        assert_eq!(buf.bytes, b"abcdef");
        assert_eq!(buf.char_count(), 6);
    }

    #[test]
    fn debug_redacted() {
        let buf = filled("EXAMPLE-pw");
        let shown = format!("{buf:?}");
        assert!(!shown.contains("EXAMPLE"));
        assert!(!shown.contains("69"), "no byte values: {shown}");
        assert_eq!(shown, "SecretInput(<10 chars hidden>)");
    }

    #[test]
    fn buffer_wiped_after_take() {
        let mut buf = filled("EXAMPLE-master-pw");
        let capacity = buf.bytes.capacity();
        let password = buf.take_master_password();
        assert!(buf.is_empty());
        assert_eq!(buf.bytes.capacity(), capacity);
        assert_eq!(buf.cap, MASTER_CAP);
        assert_eq!(password.to_kdf_bytes().expose(), b"EXAMPLE-master-pw");
        // The buffer still works after the take.
        buf.push_str("x");
        assert_eq!(buf.char_count(), 1);
    }

    #[test]
    fn take_secret_text_moves_the_text() {
        let mut buf =
            SecretInput::from_secret("EXAMPLE-secret", ITEM_SECRET_CAP).expect("fits the cap");
        let text = buf.take_secret_text();
        assert_eq!(text.expose(), "EXAMPLE-secret");
        assert!(buf.is_empty());
        assert_eq!(buf.cap, ITEM_SECRET_CAP);
    }

    #[test]
    fn to_master_password_copies_and_keeps_the_buffer() {
        let buf = filled("EXAMPLE-pw");
        let password = buf.to_master_password();
        assert_eq!(password.to_kdf_bytes().expose(), b"EXAMPLE-pw");
        assert_eq!(buf.char_count(), 10);
    }

    #[test]
    fn eq_secret_works() {
        let a = filled("EXAMPLE-pw");
        let b = filled("EXAMPLE-pw");
        let c = filled("EXAMPLE-px");
        let d = filled("EXAMPLE-p");
        assert!(a.eq_secret(&b));
        assert!(!a.eq_secret(&c));
        assert!(!a.eq_secret(&d));
        assert!(filled("").eq_secret(&filled("")));
    }

    #[test]
    fn clear_empties_and_keeps_the_allocation() {
        let mut buf = filled("EXAMPLE-pw");
        let ptr = buf.bytes.as_ptr();
        let capacity = buf.bytes.capacity();
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.bytes.as_ptr(), ptr);
        assert_eq!(buf.bytes.capacity(), capacity);
    }

    #[test]
    fn from_secret_round_trips_byte_exact() {
        // Core allows a tab (and other controls except NUL, CR and LF) in item secrets,
        // so a stored secret must come back unchanged after an edit with no typing.
        for stored in ["EXAMPLE\tpw", "EXAMPLE\u{7f}\u{85}pw", "EXAMPLE-é€😀"] {
            let mut buf = SecretInput::from_secret(stored, ITEM_SECRET_CAP).expect("fits");
            assert_eq!(buf.bytes, stored.as_bytes());
            assert_eq!(buf.cap, ITEM_SECRET_CAP);
            assert_eq!(buf.take_secret_text().expose(), stored);
        }
        // Exactly at the cap is accepted.
        let buf = SecretInput::from_secret("EXAM", 4).expect("fits exactly");
        assert_eq!(buf.bytes, b"EXAM");
    }

    #[test]
    fn from_secret_over_cap_is_refused() {
        assert!(SecretInput::from_secret("EXAMPLE", 4).is_none());
        // A multi-byte character that would cross the cap is refused, not cut.
        assert!(SecretInput::from_secret("EXAé", 4).is_none());
        let too_long = "x".repeat(ITEM_SECRET_CAP + 1);
        assert!(SecretInput::from_secret(&too_long, ITEM_SECRET_CAP).is_none());
    }

    #[test]
    fn caps_match_core_limits() {
        assert_eq!(MASTER_CAP, 4 * holm_core::strength::MAX_MASTER_CHARS);
        assert_eq!(ITEM_SECRET_CAP, holm_core::rules::MAX_SECRET_BYTES);
    }
}
