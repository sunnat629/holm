//! Body padding: hides the exact size of the vault contents.
//!
//! The padded body is a 4-byte little-endian length, then the plaintext, then
//! zero bytes up to the next multiple of [`PAD_BLOCK`] (16 KiB). The file size
//! then reveals only how many 16 KiB blocks the body needs, not its exact length.
//!
//! [`unpad`] runs only on plaintext that already passed AEAD authentication,
//! so a padding error means a buggy writer, never a wrong password or an
//! attacker's edit. It is `pub` so fuzz targets and property tests can call it.

use holm_crypto::SecretBuf;
use holm_crypto::aead::TAG_LEN;
use zeroize::Zeroizing;

use crate::envelope::VaultError;
use crate::format::{HEADER_LEN, MAX_FILE_LEN};

/// Padding block size in bytes (16 KiB). Padded bodies are a multiple of this.
pub const PAD_BLOCK: usize = 16_384;
/// Largest padded body: 4095 blocks, the most that fits in a
/// [`MAX_FILE_LEN`] file next to the header and the tag.
pub const MAX_PADDED_LEN: usize = 67_092_480;
/// Largest plaintext body that [`pad`] accepts (the padded maximum minus the
/// 4-byte length prefix).
pub const MAX_BODY_LEN: usize = MAX_PADDED_LEN - LEN_PREFIX;

/// Size of the little-endian `u32` length prefix.
const LEN_PREFIX: usize = 4;

// If any of these break, a saved file could be one `Header::parse` refuses.
const _: () = {
    assert!(MAX_PADDED_LEN.is_multiple_of(PAD_BLOCK));
    assert!(HEADER_LEN + MAX_PADDED_LEN + TAG_LEN <= MAX_FILE_LEN);
    // It is the largest such multiple: one more block would not fit.
    assert!(HEADER_LEN + MAX_PADDED_LEN + PAD_BLOCK + TAG_LEN > MAX_FILE_LEN);
    // The length prefix is a u32, so every accepted length must fit in one.
    assert!(MAX_BODY_LEN <= u32::MAX as usize);
};

/// Pads `plaintext` to a multiple of [`PAD_BLOCK`].
///
/// Layout: `u32` little-endian length, the plaintext, then zeros. The length
/// is rounded up, so an empty body gives 16384 bytes, 16380 bytes give 16384
/// and 16381 bytes give 32768. The output is built in one allocation of the
/// final size, so no unwiped copy is left behind by a reallocation.
///
/// # Errors
/// Returns [`VaultError::TooLargeToSave`] if `plaintext` is longer than
/// [`MAX_BODY_LEN`].
pub fn pad(plaintext: &[u8]) -> Result<SecretBuf, VaultError> {
    if plaintext.len() > MAX_BODY_LEN {
        return Err(VaultError::TooLargeToSave);
    }
    let len = u32::try_from(plaintext.len()).map_err(|_| VaultError::TooLargeToSave)?;
    let padded_len = plaintext
        .len()
        .checked_add(LEN_PREFIX)
        .and_then(|n| n.checked_next_multiple_of(PAD_BLOCK))
        .ok_or(VaultError::TooLargeToSave)?;

    // Wiped on drop if anything below fails; moved out (not copied) on success.
    let mut out = Zeroizing::new(Vec::with_capacity(padded_len));
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(plaintext);
    out.resize(padded_len, 0);
    Ok(SecretBuf::from_vec(core::mem::take(&mut *out)))
}

/// Removes the padding that [`pad`] added and returns the plaintext.
///
/// Call it only on authenticated plaintext. It checks every byte of the
/// padding, without stopping at the first non-zero one.
///
/// # Errors
/// Returns [`VaultError::BadPadding`] if `padded` is empty or not a multiple
/// of [`PAD_BLOCK`], if the length prefix is larger than the bytes after it,
/// or if any padding byte is not zero.
pub fn unpad(padded: &[u8]) -> Result<SecretBuf, VaultError> {
    if padded.is_empty() || !padded.len().is_multiple_of(PAD_BLOCK) {
        return Err(VaultError::BadPadding);
    }
    let (prefix, rest) = padded
        .split_first_chunk::<LEN_PREFIX>()
        .ok_or(VaultError::BadPadding)?;
    let len = usize::try_from(u32::from_le_bytes(*prefix)).map_err(|_| VaultError::BadPadding)?;
    let (body, tail) = rest.split_at_checked(len).ok_or(VaultError::BadPadding)?;
    if tail.iter().fold(0u8, |acc, &b| acc | b) != 0 {
        return Err(VaultError::BadPadding);
    }
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(body);
    Ok(SecretBuf::from_vec(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn padded_len(n: usize) -> usize {
        pad(&vec![0xAB; n]).unwrap().len()
    }

    #[test]
    fn pad_boundaries() {
        assert_eq!(padded_len(0), 16_384);
        assert_eq!(padded_len(16_380), 16_384);
        assert_eq!(padded_len(16_381), 32_768);
    }

    #[test]
    fn pad_layout_known_answer() {
        let p = pad(b"abc").unwrap();
        let mut expected = vec![0u8; PAD_BLOCK];
        expected[..7].copy_from_slice(&[3, 0, 0, 0, b'a', b'b', b'c']);
        assert_eq!(p.expose(), expected.as_slice());
    }

    #[test]
    fn pad_then_unpad_roundtrip() {
        for n in [0, 1, 100, 16_380, 16_381, 40_000] {
            let body: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let p = pad(&body).unwrap();
            assert_eq!(
                unpad(p.expose()).unwrap().expose(),
                body.as_slice(),
                "n {n}"
            );
        }
    }

    #[test]
    fn max_padded_len_is_4095_blocks() {
        assert_eq!(MAX_PADDED_LEN, 4095 * PAD_BLOCK);
        assert_eq!(MAX_BODY_LEN, MAX_PADDED_LEN - 4);
    }

    #[test]
    fn pad_rejects_body_over_max() {
        let big = vec![0u8; MAX_BODY_LEN + 1];
        assert_eq!(pad(&big).unwrap_err(), VaultError::TooLargeToSave);
    }

    #[test]
    fn unpad_rejects_length_prefix_larger_than_buffer() {
        let mut p = pad(b"abc").unwrap().expose().to_vec();
        // PAD_BLOCK - 4 bytes follow the prefix; one more is too many.
        let too_long = u32::try_from(PAD_BLOCK - 3).unwrap();
        p[..4].copy_from_slice(&too_long.to_le_bytes());
        assert_eq!(unpad(&p).unwrap_err(), VaultError::BadPadding);
        p[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(unpad(&p).unwrap_err(), VaultError::BadPadding);
        // Exactly the bytes after the prefix is still accepted.
        let exact = u32::try_from(PAD_BLOCK - 4).unwrap();
        p[..4].copy_from_slice(&exact.to_le_bytes());
        assert_eq!(unpad(&p).unwrap().len(), PAD_BLOCK - 4);
    }

    #[test]
    fn unpad_rejects_non_block_length() {
        let p = pad(b"abc").unwrap();
        for len in [0, 1, 3, 4, PAD_BLOCK - 1, PAD_BLOCK + 1] {
            let mut v = p.expose().to_vec();
            v.resize(len, 0);
            assert_eq!(unpad(&v).unwrap_err(), VaultError::BadPadding, "len {len}");
        }
    }

    #[test]
    fn unpad_rejects_nonzero_padding() {
        let p = pad(b"abc").unwrap();
        for i in [7, 8, 100, PAD_BLOCK - 1] {
            let mut v = p.expose().to_vec();
            v[i] = 1;
            assert_eq!(unpad(&v).unwrap_err(), VaultError::BadPadding, "byte {i}");
        }
    }
}
