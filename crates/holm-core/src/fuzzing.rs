//! Test-only entry points for the fuzz targets. Never part of a shipping build.
//!
//! [`seal_with_kek`] and [`open_with_kek`] skip Argon2: the caller hands in the
//! key-encryption key directly. That turns a full open into microseconds, so
//! the fuzzer can reach the body decode thousands of times a second. The same
//! shortcut in a real build would let anyone holding a key bypass the password
//! policy, which is why the module needs the `fuzzing` feature (or `cfg(test)`).

use holm_crypto::SecretKey;
use holm_crypto::kdf::KdfParams;

use crate::body::VaultData;
use crate::envelope::{self, VaultError};
use crate::error::CoreError;

/// Seals `body_plaintext` into a complete vault file under `kek`.
///
/// The header carries [`KdfParams::FLOOR`] and an all-zero salt. Neither is
/// used: [`open_with_kek`] takes the KEK directly.
///
/// # Errors
/// [`VaultError::TooLargeToSave`] for a body over the size cap,
/// [`VaultError::Crypto`] if randomness fails.
pub fn seal_with_kek(kek: &SecretKey, body_plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let (_keys, file) = envelope::create_with_kek(kek, [0; 32], &KdfParams::FLOOR, body_plaintext)?;
    Ok(file)
}

/// Opens a vault file with `kek` and decodes its body: everything an unlock
/// does after Argon2.
///
/// # Errors
/// [`CoreError::Vault`] for any file the envelope refuses,
/// [`CoreError::Body`] for an authenticated body that does not decode.
pub fn open_with_kek(file: &[u8], kek: &SecretKey) -> Result<VaultData, CoreError> {
    let (_keys, plaintext) = envelope::open_with_kek(file, kek)?;
    Ok(VaultData::decode(plaintext.expose())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek(byte: u8) -> SecretKey {
        SecretKey::from_bytes(&mut [byte; 32])
    }

    #[test]
    fn seal_then_open_gives_the_same_body() {
        let body = VaultData::new_default().encode().expect("default encodes");
        let file = seal_with_kek(&kek(7), body.expose()).expect("seals");
        let data = open_with_kek(&file, &kek(7)).expect("opens");
        assert_eq!(data.item_count(), 0);
        assert_eq!(data.encode().expect("re-encodes").expose(), body.expose());
    }

    #[test]
    fn any_flipped_byte_or_other_key_is_refused() {
        let body = VaultData::new_default().encode().expect("default encodes");
        let file = seal_with_kek(&kek(7), body.expose()).expect("seals");
        assert!(matches!(
            open_with_kek(&file, &kek(8)),
            Err(CoreError::Vault(VaultError::WrongPasswordOrCorrupt))
        ));
        for i in [0, 59, 60, 163, 164, file.len() - 1] {
            let mut bad = file.clone();
            bad[i] ^= 0x01;
            assert!(open_with_kek(&bad, &kek(7)).is_err(), "byte {i}");
        }
    }

    #[test]
    fn an_authenticated_body_that_does_not_decode_is_a_body_error() {
        let file = seal_with_kek(&kek(7), b"not postcard").expect("seals");
        assert!(matches!(
            open_with_kek(&file, &kek(7)),
            Err(CoreError::Body(_))
        ));
    }
}
