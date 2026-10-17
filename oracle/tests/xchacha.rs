//! Cross-checks holm-crypto's XChaCha20-Poly1305 against libsodium on seeded
//! pseudo-random inputs.

use holm_crypto::SecretKey;
use holm_crypto::aead::{NONCE_LEN, open, seal};
use holm_oracle::{sodium_init, xchacha_encrypt};

/// SplitMix64: a tiny, fixed pseudo-random generator, so every run tests the
/// same inputs and no `rand` dependency is needed.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next_u64() % n as u64).expect("value below n fits in usize")
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64().to_le_bytes()[0]).collect()
    }
}

#[test]
fn libsodium_matches_for_random_inputs() {
    sodium_init();
    let mut rng = SplitMix64(0x484f_4c4d_5843_4841);

    for case in 0..100 {
        let key_bytes: [u8; 32] = rng.bytes(32).try_into().expect("32 bytes");
        let nonce: [u8; NONCE_LEN] = rng.bytes(NONCE_LEN).try_into().expect("24 bytes");
        // Pin both ends of each range, the rest are random.
        let (aad_len, msg_len) = match case {
            0 => (0, 0),
            1 => (64, 1024),
            _ => (rng.below(65), rng.below(1025)),
        };
        let aad = rng.bytes(aad_len);
        let msg = rng.bytes(msg_len);

        let key = SecretKey::from_slice(&key_bytes).expect("32-byte key");
        let ours = seal(&key, &nonce, &aad, &msg).expect("seal");
        let theirs = xchacha_encrypt(&key_bytes, &nonce, &aad, &msg);
        assert_eq!(
            ours, theirs,
            "case {case}: holm-crypto and libsodium disagree"
        );

        let opened = open(&key, &nonce, &aad, &theirs).expect("open libsodium output");
        assert_eq!(
            opened.expose(),
            msg.as_slice(),
            "case {case}: open lost the plaintext"
        );
    }
}
