//! XChaCha20-Poly1305 authenticated encryption.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::secret::{SecretBuf, SecretKey};

/// Nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Key length in bytes.
pub const KEY_LEN: usize = 32;

/// Encrypts `plaintext` under `key` and `nonce`, authenticating `aad` too.
///
/// The output is the ciphertext followed by the 16-byte tag, so it is
/// `plaintext.len() + TAG_LEN` bytes long. The nonce must be random (from the
/// OS RNG) and never reused with the same key.
///
/// # Errors
/// Returns [`CryptoError::Aead`] if the cipher rejects the input (for example
/// an input too long for the algorithm).
pub fn seal(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    // The working buffer briefly holds the plaintext, so wipe it if we fail.
    let mut buf = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_LEN));
    buf.extend_from_slice(plaintext);
    cipher
        .encrypt_in_place(nonce.into(), aad, &mut *buf)
        .map_err(|_| CryptoError::Aead)?;
    Ok(std::mem::take(&mut *buf))
}

/// Decrypts and authenticates `ciphertext` (ciphertext followed by the tag).
///
/// All or nothing: on any failure (wrong key, nonce or AAD, a modified byte, or
/// input shorter than the tag) it returns one opaque error and no plaintext.
/// The working buffer is wiped when it is dropped, on success or failure.
///
/// # Errors
/// Returns [`CryptoError::Aead`] on any failure.
pub fn open(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBuf, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place(nonce.into(), aad, &mut *buf)
        .map_err(|_| CryptoError::Aead)?;
    Ok(SecretBuf::from_vec(std::mem::take(&mut *buf)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; KEY_LEN]).unwrap()
    }
    const NONCE: [u8; NONCE_LEN] = [7; NONCE_LEN];
    const AAD: &[u8] = b"header-v1";
    const MSG: &[u8] = b"attack at dawn";

    #[test]
    fn roundtrip() {
        let ct = seal(&key(1), &NONCE, AAD, MSG).unwrap();
        assert_eq!(ct.len(), MSG.len() + TAG_LEN);
        assert_eq!(open(&key(1), &NONCE, AAD, &ct).unwrap().expose(), MSG);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let ct = seal(&key(1), &NONCE, AAD, b"").unwrap();
        assert_eq!(ct.len(), TAG_LEN);
        assert!(open(&key(1), &NONCE, AAD, &ct).unwrap().is_empty());
    }

    #[test]
    fn wrong_key_fails() {
        let ct = seal(&key(1), &NONCE, AAD, MSG).unwrap();
        assert_eq!(
            open(&key(2), &NONCE, AAD, &ct).err(),
            Some(CryptoError::Aead)
        );
    }

    #[test]
    fn flipping_any_ciphertext_byte_fails() {
        let ct = seal(&key(1), &NONCE, AAD, MSG).unwrap();
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            assert_eq!(
                open(&key(1), &NONCE, AAD, &bad).err(),
                Some(CryptoError::Aead),
                "byte {i}"
            );
        }
    }

    #[test]
    fn flipping_any_aad_byte_fails() {
        let ct = seal(&key(1), &NONCE, AAD, MSG).unwrap();
        for i in 0..AAD.len() {
            let mut bad = AAD.to_vec();
            bad[i] ^= 0x01;
            assert_eq!(
                open(&key(1), &NONCE, &bad, &ct).err(),
                Some(CryptoError::Aead),
                "byte {i}"
            );
        }
    }

    #[test]
    fn wrong_nonce_fails() {
        let ct = seal(&key(1), &NONCE, AAD, MSG).unwrap();
        let mut other = NONCE;
        other[0] ^= 0x01;
        assert_eq!(
            open(&key(1), &other, AAD, &ct).err(),
            Some(CryptoError::Aead)
        );
    }

    #[test]
    fn truncated_below_tag_fails() {
        for len in 0..TAG_LEN {
            assert_eq!(
                open(&key(1), &NONCE, AAD, &vec![0u8; len]).err(),
                Some(CryptoError::Aead),
                "len {len}"
            );
        }
    }
}
