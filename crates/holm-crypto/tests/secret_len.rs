//! Public-API checks that kill mutants a unit test left alive (`docs/security/mutants-2026-11.md`):
//! `SecretBuf::is_empty` and `MasterPassword::raw_char_count`. The length cap on a typed
//! password depends on `raw_char_count`, so a constant answer there would be a real bug.

use holm_crypto::{MasterPassword, SecretBuf};

#[test]
fn secret_buf_empty_matches_length() {
    let empty = SecretBuf::from_vec(Vec::new());
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);

    let one = SecretBuf::from_vec(vec![7]);
    assert!(!one.is_empty());
    assert_eq!(one.len(), 1);
}

#[test]
fn raw_char_count_counts_scalars_before_normalising() {
    assert_eq!(MasterPassword::new(String::new()).raw_char_count(), 0);
    assert_eq!(MasterPassword::new("a".to_owned()).raw_char_count(), 1);
    assert_eq!(MasterPassword::new("abcde".to_owned()).raw_char_count(), 5);
    // One precomposed scalar against a letter plus a combining mark: counted as typed (not NFC).
    assert_eq!(
        MasterPassword::new("caf\u{e9}".to_owned()).raw_char_count(),
        4
    );
    assert_eq!(
        MasterPassword::new("cafe\u{301}".to_owned()).raw_char_count(),
        5
    );
    // Scalars, not bytes.
    assert_eq!(
        MasterPassword::new("\u{1F600}\u{1F600}".to_owned()).raw_char_count(),
        2
    );
}
