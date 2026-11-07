//! Every padding byte is checked, not only whether the tail is all zeros "on average".
//!
//! Added after a mutation run: folding the tail with XOR instead of OR was not caught,
//! because two equal non-zero bytes cancel out under XOR.

use holm_core::envelope::VaultError;
use holm_core::padding::{PAD_BLOCK, pad, unpad};

fn padded_small() -> Vec<u8> {
    pad(b"EXAMPLE body").expect("small input").expose().to_vec()
}

#[test]
fn clean_padding_round_trips() {
    let p = padded_small();
    assert_eq!(p.len(), PAD_BLOCK);
    assert_eq!(unpad(&p).expect("unpads").expose(), b"EXAMPLE body");
}

#[test]
fn two_equal_nonzero_padding_bytes_are_refused() {
    let mut p = padded_small();
    let n = p.len();
    p[n - 1] = 0x55;
    p[n - 2] = 0x55;
    assert!(matches!(unpad(&p), Err(VaultError::BadPadding)));
}

#[test]
fn any_single_nonzero_padding_byte_is_refused() {
    let base = padded_small();
    for pos in [base.len() - 1, base.len() / 2, 4 + b"EXAMPLE body".len()] {
        let mut p = base.clone();
        p[pos] = 1;
        assert!(
            matches!(unpad(&p), Err(VaultError::BadPadding)),
            "pos {pos}"
        );
    }
}

#[test]
fn bit_pairs_that_cancel_under_xor_are_refused() {
    // 0x01 ^ 0x03 ^ 0x02 == 0, and each set bit appears an even number of times.
    let mut p = padded_small();
    let n = p.len();
    p[n - 1] = 0x01;
    p[n - 2] = 0x03;
    p[n - 3] = 0x02;
    assert!(matches!(unpad(&p), Err(VaultError::BadPadding)));
}
