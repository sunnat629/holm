#![no_main]
//! A full v2 open with a fixed KEK, so no Argon2 run per input: header, key unwrap,
//! index, framing, then every record. The first byte picks the mode. Mode 0 opens the
//! rest as a raw file. Any other value seals up to 4 fixed items (the second byte picks
//! how many) and applies up to 4 `(u32 LE offset, xor)` edits from the rest. Must never
//! panic; a changed file must never open; an unchanged one must open every record.

use holm_core::fuzzing::{open_v2_all, seal_v2_with_kek};
use holm_crypto::SecretKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let kek = SecretKey::from_bytes(&mut [7; 32]);
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode == 0 {
        let _ = open_v2_all(rest, &kek);
        return;
    }
    let Some((&count, edits)) = rest.split_first() else {
        return;
    };
    let sealed = seal_v2_with_kek(&kek, count).expect("sealing the fixed items cannot fail");
    let mut file = sealed.clone();
    for edit in edits.chunks_exact(5).take(4) {
        let offset = u32::from_le_bytes([edit[0], edit[1], edit[2], edit[3]]) as usize;
        let at = offset % file.len();
        file[at] ^= edit[4];
    }
    let opened = open_v2_all(&file, &kek);
    if file == sealed {
        assert_eq!(
            opened,
            Ok(usize::from(count % 5)),
            "an unchanged file must open"
        );
    } else {
        assert!(opened.is_err(), "a changed file opened");
    }
});
