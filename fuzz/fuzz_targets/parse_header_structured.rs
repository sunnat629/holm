#![no_main]
//! Build a valid file from arbitrary fields, damage it, then parse.
//! Reaches the checks behind the magic bytes that raw fuzzing rarely gets to.

use arbitrary::Arbitrary;
use holm_core::format::{HEADER_LEN, Header};
use holm_crypto::kdf::{KdfParams, MAX_M_KIB, MAX_WORK};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Edit {
    Xor { offset: u16, value: u8 },
    Truncate { len: u16 },
    Extend { extra: Vec<u8> },
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// Mapped into the valid KDF range unless `bad_kdf` asks for raw values.
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    bad_kdf: bool,
    salt: [u8; 32],
    wrap_nonce: [u8; 24],
    wrapped_dek: [u8; 48],
    body_nonce: [u8; 24],
    body: [u8; 16],
    more_body: Vec<u8>,
    edits: Vec<Edit>,
}

fuzz_target!(|input: Input| {
    let mut body = input.body.to_vec();
    body.extend(input.more_body.iter().take(48));
    // Valid parameters most of the time, so inputs reach the length and body checks.
    let kdf = if input.bad_kdf {
        KdfParams {
            memory_kib: input.memory_kib,
            iterations: input.iterations,
            parallelism: input.parallelism,
        }
    } else {
        let iterations = 3 + input.iterations % 14;
        let max_m = u64::from(MAX_M_KIB).min(MAX_WORK / u64::from(iterations));
        let max_m = u32::try_from(max_m).expect("capped by MAX_M_KIB");
        KdfParams {
            memory_kib: 65_536 + input.memory_kib % (max_m - 65_536 + 1),
            iterations,
            parallelism: 1,
        }
    };
    let header = Header {
        kdf,
        salt: input.salt,
        wrap_nonce: input.wrap_nonce,
        wrapped_dek: input.wrapped_dek,
        body_nonce: input.body_nonce,
        body_len: body.len() as u64,
    };
    let mut bytes = header.encode().to_vec();
    bytes.extend_from_slice(&body);

    for edit in input.edits.iter().take(4) {
        match edit {
            Edit::Xor { offset, value } => {
                if !bytes.is_empty() {
                    let i = usize::from(*offset) % bytes.len();
                    bytes[i] ^= value;
                }
            }
            Edit::Truncate { len } => bytes.truncate(usize::from(*len) % (bytes.len() + 1)),
            Edit::Extend { extra } => bytes.extend(extra.iter().take(32)),
        }
    }

    if let Ok((parsed, body)) = Header::parse(&bytes) {
        assert_eq!(&parsed.encode()[..], &bytes[..HEADER_LEN]);
        assert_eq!(body, &bytes[HEADER_LEN..]);
    }
});
