//! Secret types: wiped on drop, never printed, never cloned by accident.

use core::fmt;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A 32-byte secret key, stored on the heap and wiped when dropped.
///
/// The bytes live in a `Box` so moving the key moves only a pointer, never a
/// copy of the key. There is no `Clone` or `Copy`, and `Debug` hides the bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Box<[u8; 32]>);

impl SecretKey {
    /// Copies `bytes` into a new key, then wipes the caller's array.
    ///
    /// Takes `&mut` because passing the array by value would leave an unwiped
    /// copy in the argument slot.
    #[must_use]
    pub fn from_bytes(bytes: &mut [u8; 32]) -> SecretKey {
        let mut key = SecretKey::zeroed();
        key.0.copy_from_slice(&bytes[..]);
        bytes.zeroize();
        key
    }

    /// An all-zero key, to be filled in place through [`SecretKey::expose_mut`].
    #[must_use]
    pub(crate) fn zeroed() -> SecretKey {
        // Zeros on the stack are harmless; the real bytes are written into the box.
        SecretKey(Box::new([0u8; 32]))
    }

    /// Mutable access to the key bytes, for writing them straight into the box.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "first used by key generation and derivation in Tasks 4 and 5; remove this then"
        )
    )]
    pub(crate) fn expose_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }

    /// Read-only access to the key bytes. Keep the borrow short.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

/// A variable-length secret byte buffer, wiped when dropped.
pub struct SecretBuf(Zeroizing<Vec<u8>>);

impl SecretBuf {
    /// Takes ownership of `v`. The bytes are wiped when the buffer drops.
    #[must_use]
    pub fn from_vec(v: Vec<u8>) -> SecretBuf {
        SecretBuf(Zeroizing::new(v))
    }

    /// Read-only access to the bytes. Keep the borrow short.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Number of bytes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when no bytes are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf([REDACTED], len = {})", self.len())
    }
}

/// The user's master password, wiped when dropped.
pub struct MasterPassword(Zeroizing<String>);

impl MasterPassword {
    /// Takes ownership of the password text.
    ///
    /// The caller's `String` may have been copied before it got here; we can
    /// only wipe what we hold.
    #[must_use]
    pub fn new(s: String) -> MasterPassword {
        MasterPassword(Zeroizing::new(s))
    }

    /// The password in Unicode NFC form, as UTF-8 bytes, ready for the KDF.
    ///
    /// NFC makes "caf\u{e9}" and "cafe\u{301}" produce the same key.
    #[must_use]
    pub fn to_kdf_bytes(&self) -> SecretBuf {
        // NFC grows UTF-8 by at most 3x. Reserving that up front means the
        // buffer never reallocates, so no unwiped copy is left behind.
        let mut normalized = Zeroizing::new(String::with_capacity(3 * self.0.len()));
        normalized.extend(self.0.nfc());
        let mut out = Vec::with_capacity(normalized.len());
        out.extend_from_slice(normalized.as_bytes());
        SecretBuf::from_vec(out)
    }
}

impl fmt::Debug for MasterPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterPassword([REDACTED])")
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_key_bytes() {
        let k = SecretKey::from_bytes(&mut [0xAB; 32]);
        let s = format!("{k:?}");
        assert_eq!(s, "SecretKey([REDACTED])");
    }
    #[test]
    fn from_bytes_wipes_source() {
        let mut src = [0xAB; 32];
        let k = SecretKey::from_bytes(&mut src);
        assert_eq!(src, [0u8; 32]);
        assert_eq!(k.expose(), &[0xAB; 32]);
    }
    #[test]
    fn zeroed_then_filled_in_place() {
        let mut k = SecretKey::zeroed();
        assert_eq!(k.expose(), &[0u8; 32]);
        k.expose_mut()[0] = 7;
        assert_eq!(k.expose()[0], 7);
    }
    #[test]
    fn secretbuf_debug_shows_len_only() {
        assert_eq!(
            format!("{:?}", SecretBuf::from_vec(vec![7; 5])),
            "SecretBuf([REDACTED], len = 5)"
        );
    }
    #[test]
    fn nfc_composed_and_decomposed_match() {
        let a = MasterPassword::new("caf\u{e9}".into()).to_kdf_bytes();
        let b = MasterPassword::new("cafe\u{301}".into()).to_kdf_bytes();
        assert_eq!(a.expose(), b.expose());
        assert_eq!(a.expose(), "caf\u{e9}".as_bytes());
    }
    #[test]
    fn masterpassword_debug_redacted() {
        assert_eq!(
            format!("{:?}", MasterPassword::new("hunter2".into())),
            "MasterPassword([REDACTED])"
        );
    }
    static_assertions::assert_not_impl_any!(SecretKey: Clone, Copy);
    static_assertions::assert_not_impl_any!(SecretBuf: Clone, Copy);
    static_assertions::assert_not_impl_any!(MasterPassword: Clone, Copy);
}
