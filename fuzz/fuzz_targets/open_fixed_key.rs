#![no_main]
//! A full open (envelope, padding, body decode) with a fixed KEK, so no Argon2
//! run per input. Either a raw file, or a body sealed under the same KEK and
//! then damaged. Must never panic; a changed file must never open.

use arbitrary::Arbitrary;
use holm_core::body::VaultData;
use holm_core::error::CoreError;
use holm_core::fuzzing::{open_with_kek, seal_with_kek};
use holm_crypto::SecretKey;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Input {
    RawFile(Vec<u8>),
    Sealed {
        body: Vec<u8>,
        /// `(offset, xor)` pairs; only the first 4 are applied.
        edits: Vec<(u32, u8)>,
    },
}

fn kek() -> SecretKey {
    SecretKey::from_bytes(&mut [7; 32])
}

fuzz_target!(|input: Input| {
    let kek = kek();
    match input {
        Input::RawFile(file) => {
            let _ = open_with_kek(&file, &kek);
        }
        Input::Sealed { body, edits } => {
            // An oversized body is refused before sealing: skip it.
            let Ok(sealed) = seal_with_kek(&kek, &body) else {
                return;
            };
            let mut file = sealed.clone();
            for &(offset, value) in edits.iter().take(4) {
                let i = offset as usize % file.len();
                file[i] ^= value;
            }
            let opened = open_with_kek(&file, &kek);
            if file != sealed {
                // Every byte is authenticated: any change must be refused.
                assert!(opened.is_err(), "a changed file opened");
                return;
            }
            match opened {
                Ok(data) => {
                    let encoded = data.encode().expect("a decoded body re-encodes");
                    let back = VaultData::decode(encoded.expose()).expect("and decodes");
                    assert_eq!(back.item_count(), data.item_count());
                }
                // The envelope must always open what it sealed; only the body may fail.
                Err(CoreError::Body(_)) => {}
                Err(e) => panic!("own seal refused by the envelope: {e:?}"),
            }
        }
    }
});
