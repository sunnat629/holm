//! Secret types: wiped on drop, never printed, never cloned by accident.

use crate::error::CryptoError;
use crate::random::fill_random;
use core::fmt;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A 32-byte secret key, stored on the heap and wiped when dropped.
///
/// The bytes live in a `Box` so moving the key moves only a pointer, never a
/// copy of the key. There is no `Clone` or `Copy`, and `Debug` hides the bytes.
#[derive(ZeroizeOnDrop)]
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

    /// A fresh random key from the OS, written straight into the heap box so no
    /// stack copy of the key exists.
    ///
    /// # Errors
    /// Returns [`CryptoError::Rng`] if the OS cannot provide randomness.
    pub fn generate() -> Result<SecretKey, CryptoError> {
        let mut k = SecretKey::zeroed();
        fill_random(k.expose_mut())?;
        Ok(k)
    }

    /// Copies exactly 32 bytes straight into a new key's box. No temporary
    /// buffer is made, so there is nothing extra to wipe. The caller still owns
    /// `bytes` and is responsible for wiping it.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidKeyLength`] unless `bytes.len() == 32`.
    pub fn from_slice(bytes: &[u8]) -> Result<SecretKey, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut key = SecretKey::zeroed();
        key.0.copy_from_slice(bytes);
        Ok(key)
    }

    /// An all-zero key, to be filled in place through [`SecretKey::expose_mut`].
    #[must_use]
    pub(crate) fn zeroed() -> SecretKey {
        // Zeros on the stack are harmless; the real bytes are written into the box.
        SecretKey(Box::new([0u8; 32]))
    }

    /// Mutable access to the key bytes, for writing them straight into the box.
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
    ///
    /// Copies left behind by the caller's earlier reallocations of `v`
    /// cannot be wiped; we only wipe what we hold.
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
        // NFC grows UTF-8 by at most 3x. Reserving that up front means our
        // buffer never reallocates. (The normaliser's own small scratch
        // buffers are outside our control.)
        let cap = 3 * self.0.len();
        let mut normalized = Zeroizing::new(String::with_capacity(cap));
        normalized.extend(self.0.nfc());
        debug_assert_eq!(normalized.capacity(), cap, "NFC outgrew the 3x bound");
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
    #[test]
    fn nfc_worst_case_expansion() {
        let b = MasterPassword::new("\u{1D160}".repeat(8)).to_kdf_bytes();
        assert_eq!(b.len(), 96);
    }
    #[test]
    fn empty_password_gives_empty_bytes() {
        assert!(MasterPassword::new(String::new()).to_kdf_bytes().is_empty());
    }
    #[test]
    fn empty_secretbuf_debug_len_zero() {
        assert_eq!(
            format!("{:?}", SecretBuf::from_vec(Vec::new())),
            "SecretBuf([REDACTED], len = 0)"
        );
    }
    #[test]
    fn two_generated_keys_differ() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
    }
    #[test]
    fn from_slice_accepts_32_bytes() {
        let src: Vec<u8> = (0..32).collect();
        let k = SecretKey::from_slice(&src).unwrap();
        assert_eq!(k.expose().as_slice(), src.as_slice());
    }
    #[test]
    fn from_slice_rejects_wrong_length() {
        assert_eq!(
            SecretKey::from_slice(&[0u8; 31]).unwrap_err(),
            CryptoError::InvalidKeyLength
        );
        assert_eq!(
            SecretKey::from_slice(&[0u8; 33]).unwrap_err(),
            CryptoError::InvalidKeyLength
        );
        assert_eq!(
            SecretKey::from_slice(&[]).unwrap_err(),
            CryptoError::InvalidKeyLength
        );
    }
    static_assertions::assert_not_impl_any!(SecretKey: Clone, Copy);
    static_assertions::assert_not_impl_any!(SecretBuf: Clone, Copy);
    static_assertions::assert_not_impl_any!(MasterPassword: Clone, Copy);
}
