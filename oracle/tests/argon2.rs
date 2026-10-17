//! Cross-checks holm-crypto's Argon2id against libsodium on seeded
//! pseudo-random passwords, at the floor costs Holm accepts.

use holm_crypto::MasterPassword;
use holm_crypto::kdf::{KdfParams, argon2id_raw};
use holm_oracle::{argon2id13, sodium_init};

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
}

/// ASCII plus non-ASCII characters, including combining marks (U+0301,
/// U+030A) that NFC merges with the letter before them.
const ALPHABET: &str = "aZ7 !~eA\u{e9}\u{301}\u{30a}\u{df}\u{f1}\u{3a9}\u{6f22}\u{1f511}";

/// Runs Argon2id through holm-crypto and through libsodium with the same
/// inputs and fails if the two 32-byte tags differ.
fn assert_same_tag(params: KdfParams, pw: &[u8], salt: &[u8; 16], label: &str) {
    let memlimit_bytes = usize::try_from(params.memory_kib).expect("u32 fits in usize") * 1024;
    let mut ours = [0u8; 32];
    argon2id_raw(
        pw,
        salt,
        &[],
        &[],
        params.memory_kib,
        params.iterations,
        params.parallelism,
        &mut ours,
    )
    .expect("holm-crypto Argon2id failed");
    let theirs = argon2id13(pw, salt, u64::from(params.iterations), memlimit_bytes);
    assert_eq!(ours, theirs, "{label}: holm-crypto and libsodium disagree");
}

#[test]
fn argon2id_matches_libsodium() {
    sodium_init();
    let alphabet: Vec<char> = ALPHABET.chars().collect();
    let mut rng = SplitMix64(0x484f_4c4d_4f52_4143);
    let mut nfc_changed_bytes = 0;

    for case in 0..20 {
        // Cover both ends of 0..=64 for sure, the rest at random.
        let len = match case {
            0 => 0,
            1 => 64,
            _ => rng.below(65),
        };
        let text: String = (0..len)
            .map(|_| alphabet[rng.below(alphabet.len())])
            .collect();
        let mut salt = [0u8; 16];
        for b in &mut salt {
            *b = rng.next_u64().to_le_bytes()[0];
        }

        // Both sides get the NFC bytes, exactly as derive_kek does.
        let pw = MasterPassword::new(text.clone()).to_kdf_bytes();
        if pw.expose() != text.as_bytes() {
            nfc_changed_bytes += 1;
        }
        assert_same_tag(
            KdfParams::FLOOR,
            pw.expose(),
            &salt,
            &format!("case {case}"),
        );
    }

    // Guard against a generator change that would stop testing NFC at all.
    assert!(nfc_changed_bytes > 0, "no case exercised NFC normalisation");
}

#[test]
fn argon2id_matches_libsodium_above_floor() {
    // The shipping DEFAULT and an odd, non-power-of-two cost, so the
    // cross-check is not only ever run at FLOOR.
    sodium_init();
    let odd = KdfParams {
        memory_kib: 73728,
        iterations: 4,
        parallelism: 1,
    };
    let pw = MasterPassword::new("cafe\u{301} \u{1f511} horse".into()).to_kdf_bytes();
    for (params, label) in [(KdfParams::DEFAULT, "DEFAULT"), (odd, "73728/4")] {
        assert!(
            params.validate().is_ok(),
            "{label} must be an accepted cost"
        );
        assert_same_tag(params, pw.expose(), &[0x5a; 16], label);
    }
}
