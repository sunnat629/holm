//! Known-answer tests for XChaCha20-Poly1305: the IETF draft vector and the
//! Wycheproof suite pinned in `tests/vectors/`.

use holm_crypto::SecretKey;
use holm_crypto::aead::{NONCE_LEN, TAG_LEN, open, seal};
use holm_crypto::error::CryptoError;

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
        &hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap(),
    );
    let nonce: [u8; NONCE_LEN] = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657")
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

    assert_eq!(seal(&key, &nonce, &aad, &plaintext).unwrap(), expected);
    let opened = open(&key, &nonce, &aad, &expected).unwrap();
    assert_eq!(opened.expose(), plaintext.as_slice());
}

/// Counts asserted below come from `tests/vectors/README.md`.
const EXPECTED_SKIPPED: usize = 9;

#[test]
fn wycheproof_all_cases() {
    let raw = include_str!("vectors/xchacha20_poly1305_test.json");
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
                skipped += 1;
                continue;
            };
            // A key or tag of the wrong size is a test-harness problem, not a skip.
            let key = SecretKey::from_slice(&key);
            let mut sealed = ct;
            sealed.extend_from_slice(&tag);

            if result == "valid" {
                let key = key.unwrap_or_else(|_| panic!("tcId {tc_id}: valid case with bad key"));
                assert_eq!(tag.len(), TAG_LEN, "tcId {tc_id}");
                assert_eq!(
                    seal(&key, &nonce, &aad, &msg).unwrap(),
                    sealed,
                    "tcId {tc_id} seal"
                );
                let opened = open(&key, &nonce, &aad, &sealed).expect("valid case must open");
                assert_eq!(opened.expose(), msg.as_slice(), "tcId {tc_id} open");
            } else if let Ok(key) = key {
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
