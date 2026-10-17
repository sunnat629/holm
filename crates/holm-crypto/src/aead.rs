//! XChaCha20-Poly1305 authenticated encryption.
//!
//! Key hygiene: our code never copies the key out of [`SecretKey`]. The
//! cipher struct built by `KeyInit::new` holds its own copy, which the crate
//! wipes on drop (`zeroize` feature). The HChaCha20 subkey derived inside the
//! upstream `chacha20` crate is not zeroized by that crate, so a short-lived
//! copy of it can remain in memory after a call. This is an upstream gap that
//! we cannot close from here.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::random::random_array;
use crate::secret::{SecretBuf, SecretKey};

/// Nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Key length in bytes.
pub const KEY_LEN: usize = 32;

/// A 24-byte XChaCha20 nonce that can be used for exactly one [`seal`].
///
/// Reusing a nonce with the same key destroys the security of the cipher, so
/// this type makes reuse impossible in safe code:
/// - the only public way to make one is [`Nonce::random`], which draws from
///   the OS RNG;
/// - it is neither `Clone` nor `Copy`, and [`seal`] takes it by value, so it
///   is consumed by the call and cannot be used for a second `seal`.
///
/// To store the nonce next to the ciphertext, read it with [`Nonce::as_bytes`]
/// before sealing. [`open`] takes a plain `&[u8; 24]`, since opening may reuse
/// a nonce read back from a file.
#[derive(Debug)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Draws a fresh random nonce from the OS RNG.
    ///
    /// # Errors
    /// Returns [`CryptoError::Rng`] if the OS cannot provide randomness.
    pub fn random() -> Result<Self, CryptoError> {
        Ok(Self(random_array::<NONCE_LEN>()?))
    }

    /// The nonce bytes, for writing them into a file or header.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    /// Builds a nonce from fixed bytes. Tests only: known-answer vectors need
    /// a fixed nonce.
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }
}

/// Encrypts `plaintext` under `key` and `nonce`, authenticating `aad` too.
/// The nonce is consumed, so it cannot be used for a second seal.
///
/// The output is the ciphertext followed by the 16-byte tag, so it is
/// `plaintext.len() + TAG_LEN` bytes long.
///
/// # Errors
/// Returns [`CryptoError::Aead`] if the cipher rejects the input (for example
/// an input too long for the algorithm).
pub fn seal(
    key: &SecretKey,
    nonce: Nonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    // The working buffer briefly holds the plaintext, so wipe it if we fail.
    let mut buf = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_LEN));
    buf.extend_from_slice(plaintext);
    cipher
        .encrypt_in_place((&nonce.0).into(), aad, &mut *buf)
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
    fn nonce() -> Nonce {
        Nonce::from_bytes(NONCE)
    }
    const AAD: &[u8] = b"header-v1";
    const MSG: &[u8] = b"attack at dawn";

    #[test]
    fn roundtrip() {
        let ct = seal(&key(1), nonce(), AAD, MSG).unwrap();
        assert_eq!(ct.len(), MSG.len() + TAG_LEN);
        assert_eq!(open(&key(1), &NONCE, AAD, &ct).unwrap().expose(), MSG);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let ct = seal(&key(1), nonce(), AAD, b"").unwrap();
        assert_eq!(ct.len(), TAG_LEN);
        assert!(open(&key(1), &NONCE, AAD, &ct).unwrap().is_empty());
    }

    #[test]
    fn wrong_key_fails() {
        let ct = seal(&key(1), nonce(), AAD, MSG).unwrap();
        assert_eq!(
            open(&key(2), &NONCE, AAD, &ct).err(),
            Some(CryptoError::Aead)
        );
    }

    #[test]
    fn flipping_any_ciphertext_byte_fails() {
        let ct = seal(&key(1), nonce(), AAD, MSG).unwrap();
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
        let ct = seal(&key(1), nonce(), AAD, MSG).unwrap();
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
        let ct = seal(&key(1), nonce(), AAD, MSG).unwrap();
        let mut other = NONCE;
        other[0] ^= 0x01;
        assert_eq!(
            open(&key(1), &other, AAD, &ct).err(),
            Some(CryptoError::Aead)
        );
    }

    #[test]
    fn random_nonces_differ() {
        let a = Nonce::random().unwrap();
        let b = Nonce::random().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
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

/// Known-answer tests: the IETF draft vector and the Wycheproof suite pinned in
/// `tests/vectors/`. They live here (not in `tests/`) because `Nonce::from_bytes`
/// is test-only.
#[cfg(test)]
mod kat {
    use super::*;

    fn key_from(bytes: &[u8]) -> SecretKey {
        SecretKey::from_slice(bytes).expect("32-byte key")
    }

    /// draft-irtf-cfrg-xchacha-03, Appendix A.3.1 (AEAD_XCHACHA20_POLY1305):
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt>
    #[test]
    fn draft_xchacha_a3_1() {
        let plaintext = hex::decode(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
             637265656e20776f756c642062652069742e",
        )
        .unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let key = key_from(
            &hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap(),
        );
        let nonce: [u8; NONCE_LEN] =
            hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657")
                .unwrap()
                .try_into()
                .unwrap();
        let ciphertext = hex::decode(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52e",
        )
        .unwrap();
        let tag = hex::decode("c0875924c1c7987947deafd8780acf49").unwrap();

        let mut expected = ciphertext;
        expected.extend_from_slice(&tag);

        assert_eq!(
            seal(&key, Nonce::from_bytes(nonce), &aad, &plaintext).unwrap(),
            expected
        );
        let opened = open(&key, &nonce, &aad, &expected).unwrap();
        assert_eq!(opened.expose(), plaintext.as_slice());
    }

    /// Counts asserted below come from `tests/vectors/README.md`.
    const EXPECTED_SKIPPED: usize = 9;

    #[test]
    fn wycheproof_all_cases() {
        let raw = include_str!("../tests/vectors/xchacha20_poly1305_test.json");
        let root: serde_json::Value = serde_json::from_str(raw).expect("valid JSON");
        let declared = root["numberOfTests"].as_u64().expect("numberOfTests") as usize;

        let mut checked = 0usize;
        let mut skipped = 0usize;
        for group in root["testGroups"].as_array().expect("testGroups") {
            for case in group["tests"].as_array().expect("tests") {
                let tc_id = case["tcId"].as_u64().expect("tcId");
                let field = |name: &str| hex::decode(case[name].as_str().expect(name)).expect(name);
                let result = case["result"].as_str().expect("result");
                assert!(
                    result == "valid" || result == "invalid",
                    "tcId {tc_id}: unexpected result {result}"
                );
                let (key, iv, aad, msg, ct, tag) = (
                    field("key"),
                    field("iv"),
                    field("aad"),
                    field("msg"),
                    field("ct"),
                    field("tag"),
                );

                let Ok(nonce) = <[u8; NONCE_LEN]>::try_from(iv.as_slice()) else {
                    assert_eq!(
                        result, "invalid",
                        "tcId {tc_id}: skipped case must be invalid"
                    );
                    let flags = case["flags"].as_array().expect("flags");
                    assert!(
                        flags.iter().any(|f| f == "InvalidNonceSize"),
                        "tcId {tc_id}: skipped case must carry InvalidNonceSize"
                    );
                    skipped += 1;
                    continue;
                };

                let key = SecretKey::from_slice(&key)
                    .unwrap_or_else(|_| panic!("tcId {tc_id}: test vector has a bad key"));
                let mut sealed = ct;
                sealed.extend_from_slice(&tag);

                if result == "valid" {
                    assert_eq!(tag.len(), TAG_LEN, "tcId {tc_id}");
                    assert_eq!(
                        seal(&key, Nonce::from_bytes(nonce), &aad, &msg).unwrap(),
                        sealed,
                        "tcId {tc_id} seal"
                    );
                    let opened = open(&key, &nonce, &aad, &sealed).expect("valid case must open");
                    assert_eq!(opened.expose(), msg.as_slice(), "tcId {tc_id} open");
                } else {
                    assert_eq!(
                        open(&key, &nonce, &aad, &sealed).err(),
                        Some(CryptoError::Aead),
                        "tcId {tc_id}: invalid case must fail"
                    );
                }
                checked += 1;
            }
        }
        assert_eq!(
            checked + skipped,
            declared,
            "every case is checked or skipped"
        );
        assert_eq!(
            skipped, EXPECTED_SKIPPED,
            "skipped count changed; see vectors/README.md"
        );
    }
}
