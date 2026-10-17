#![no_main]
//! Build a valid file from arbitrary fields, damage it, then parse.
//! Reaches the checks behind the magic bytes that raw fuzzing rarely gets to.

use arbitrary::Arbitrary;
use holm_core::format::{HEADER_LEN, Header};
use holm_crypto::kdf::KdfParams;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Edit {
    Xor { offset: u16, value: u8 },
    Truncate { len: u16 },
    Extend { extra: Vec<u8> },
}

#[derive(Arbitrary, Debug)]
struct Input {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
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
    let header = Header {
        kdf: KdfParams {
            memory_kib: input.memory_kib,
            iterations: input.iterations,
            parallelism: input.parallelism,
        },
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

    if let Ok((parsed, _body)) = Header::parse(&bytes) {
        assert_eq!(&parsed.encode()[..], &bytes[..HEADER_LEN]);
    }
});
