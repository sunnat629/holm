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

/// Record padding block size in bytes. Each sealed record plaintext is padded to
/// a multiple of this, so a typical login is one block whatever its password length.
pub const RECORD_PAD_BLOCK: usize = 256;
/// Largest padded record plaintext (256 KiB). A multiple of [`RECORD_PAD_BLOCK`].
pub const MAX_RECORD_PADDED: usize = 262_144;

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
    // Records: block-aligned cap that also fits the u32 prefix.
    assert!(MAX_RECORD_PADDED.is_multiple_of(RECORD_PAD_BLOCK));
    assert!(MAX_RECORD_PADDED <= u32::MAX as usize);
    // The worst record (spec 2.8): a 4096-byte password, 65 536-byte notes and ten
    // 16 384-byte multiline secrets, plus 1 KiB of framing, plus the prefix.
    assert!(4096 + 65_536 + 10 * 16_384 + 1024 + LEN_PREFIX <= MAX_RECORD_PADDED);
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
    pad_to(plaintext, PAD_BLOCK, MAX_PADDED_LEN)
}

/// [`pad`] with a chosen block size and cap.
///
/// `max_padded` must be a multiple of `block` and at least `block`; the plaintext
/// is refused when its padded form would exceed it. One allocation of the final
/// size, so no unwiped copy is left behind by a reallocation.
///
/// # Errors
/// Returns [`VaultError::TooLargeToSave`] if the padded form would be larger than
/// `max_padded`, or if `block` is zero.
pub(crate) fn pad_to(
    plaintext: &[u8],
    block: usize,
    max_padded: usize,
) -> Result<SecretBuf, VaultError> {
    if block == 0 || plaintext.len() > max_padded.saturating_sub(LEN_PREFIX) {
        return Err(VaultError::TooLargeToSave);
    }
    // Unreachable errors for the built-in caps; a caller with a bigger cap gets a clean error.
    let len = u32::try_from(plaintext.len()).map_err(|_| VaultError::TooLargeToSave)?;
    let padded_len = plaintext
        .len()
        .checked_add(LEN_PREFIX)
        .and_then(|n| n.checked_next_multiple_of(block))
        .ok_or(VaultError::TooLargeToSave)?;
    if padded_len > max_padded {
        return Err(VaultError::TooLargeToSave);
    }

    // Wiped on drop if anything below fails; moved out (not copied) on success.
    let mut out = Zeroizing::new(Vec::with_capacity(padded_len));
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(plaintext);
    out.resize(padded_len, 0);
    Ok(SecretBuf::from_vec(core::mem::take(&mut *out)))
}

/// Removes the padding that [`pad`] added and returns the plaintext.
///
/// Call it only on authenticated plaintext. Padding must be canonical: the
/// buffer must be exactly the length [`pad`] would produce for that body, so
/// each body has one padded form. Every padding byte is checked, without
/// stopping at the first non-zero one.
///
/// # Errors
/// Returns [`VaultError::BadPadding`] if `padded` is empty or not a multiple
/// of [`PAD_BLOCK`], if the length prefix is larger than the bytes after it,
/// if the buffer has more blocks than the body needs, or if any padding byte
/// is not zero.
pub fn unpad(padded: &[u8]) -> Result<SecretBuf, VaultError> {
    unpad_from(padded, PAD_BLOCK)
}

/// [`unpad`] with a chosen block size.
///
/// # Errors
/// Returns [`VaultError::BadPadding`] under the same rules as [`unpad`], with
/// `block` in place of [`PAD_BLOCK`] (and for a zero `block`).
pub(crate) fn unpad_from(padded: &[u8], block: usize) -> Result<SecretBuf, VaultError> {
    if block == 0 || padded.is_empty() || !padded.len().is_multiple_of(block) {
        return Err(VaultError::BadPadding);
    }
    let (prefix, rest) = padded
        .split_first_chunk::<LEN_PREFIX>()
        .ok_or(VaultError::BadPadding)?;
    let len = usize::try_from(u32::from_le_bytes(*prefix)).map_err(|_| VaultError::BadPadding)?;
    let minimal = len
        .checked_add(LEN_PREFIX)
        .and_then(|n| n.checked_next_multiple_of(block))
        .ok_or(VaultError::BadPadding)?;
    if minimal != padded.len() {
        return Err(VaultError::BadPadding);
    }
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
    fn unpad_rejects_non_minimal_padding() {
        // A 3-byte body needs one block; two blocks are not canonical.
        let mut v = pad(b"abc").unwrap().expose().to_vec();
        v.resize(2 * PAD_BLOCK, 0);
        assert_eq!(unpad(&v).unwrap_err(), VaultError::BadPadding);
        // A 16381-byte body needs exactly two blocks, so this length is fine.
        v[..4].copy_from_slice(&16_381u32.to_le_bytes());
        assert_eq!(unpad(&v).unwrap().len(), 16_381);
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

    fn rec_len(n: usize) -> usize {
        pad_to(&vec![0xCD; n], RECORD_PAD_BLOCK, MAX_RECORD_PADDED)
            .unwrap()
            .len()
    }

    #[test]
    fn record_pad_boundaries() {
        assert_eq!(rec_len(0), 256);
        assert_eq!(rec_len(252), 256);
        assert_eq!(rec_len(253), 512);
    }

    #[test]
    fn record_pad_canonical() {
        let p = pad_to(b"abc", RECORD_PAD_BLOCK, MAX_RECORD_PADDED).unwrap();
        assert_eq!(p.len(), 256);
        assert_eq!(
            unpad_from(p.expose(), RECORD_PAD_BLOCK).unwrap().expose(),
            b"abc"
        );
        // Longer, shorter, mis-aligned and nonzero-fill forms are all refused.
        let mut longer = p.expose().to_vec();
        longer.resize(512, 0);
        let mut shorter = p.expose().to_vec();
        shorter.truncate(255);
        let mut dirty = p.expose().to_vec();
        dirty[255] = 1;
        for bad in [longer, shorter, dirty] {
            assert_eq!(
                unpad_from(&bad, RECORD_PAD_BLOCK).unwrap_err(),
                VaultError::BadPadding
            );
        }
    }

    #[test]
    fn record_pad_cap() {
        let max_body = MAX_RECORD_PADDED - 4;
        let ok = pad_to(&vec![1u8; max_body], RECORD_PAD_BLOCK, MAX_RECORD_PADDED).unwrap();
        assert_eq!(ok.len(), MAX_RECORD_PADDED);
        assert_eq!(
            pad_to(
                &vec![1u8; max_body + 1],
                RECORD_PAD_BLOCK,
                MAX_RECORD_PADDED
            )
            .unwrap_err(),
            VaultError::TooLargeToSave
        );
        assert_eq!(
            pad_to(b"x", 0, 256).unwrap_err(),
            VaultError::TooLargeToSave
        );
    }

    #[test]
    fn unpad_from_rejects_extra_block() {
        for block in [RECORD_PAD_BLOCK, PAD_BLOCK] {
            let mut v = pad_to(b"abc", block, 4 * block).unwrap().expose().to_vec();
            v.resize(v.len() + block, 0);
            assert_eq!(unpad_from(&v, block).unwrap_err(), VaultError::BadPadding);
        }
        assert_eq!(unpad_from(&[0; 8], 0).unwrap_err(), VaultError::BadPadding);
    }

    proptest::proptest! {
        #[test]
        fn pad_to_roundtrip_any_block(
            body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2000),
            block in 8usize..600,
        ) {
            let max = 4096 * block;
            let p = pad_to(&body, block, max).unwrap();
            proptest::prop_assert_eq!(p.len() % block, 0);
            proptest::prop_assert!(p.len() >= body.len() + 4 && p.len() < body.len() + 4 + block);
            let back = unpad_from(p.expose(), block).unwrap();
            proptest::prop_assert_eq!(back.expose(), body.as_slice());
        }
    }
}
