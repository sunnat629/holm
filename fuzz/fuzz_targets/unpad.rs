#![no_main]
//! Either raw bytes or damaged `pad` output into `unpad`. Must never panic.

use arbitrary::Arbitrary;
use holm_core::padding::{PAD_BLOCK, pad, unpad};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Edit {
    Xor { offset: u32, value: u8 },
    Truncate { len: u32 },
    Extend { extra: Vec<u8> },
    AppendBlocks { n: u8 },
    DropBlock,
}

#[derive(Arbitrary, Debug)]
enum Input {
    Raw(Vec<u8>),
    Padded {
        plaintext: Vec<u8>,
        edits: Vec<Edit>,
    },
}

fuzz_target!(|input: Input| {
    match input {
        Input::Raw(bytes) => {
            if let Ok(out) = unpad(&bytes) {
                let again = pad(out.expose()).expect("accepted input fits");
                assert_eq!(again.expose(), &bytes[..]);
            }
        }
        Input::Padded { plaintext, edits } => {
            let Ok(padded) = pad(&plaintext) else { return };
            let mut bytes = padded.expose().to_vec();
            // An unedited pad output must always come back.
            let back = unpad(&bytes).expect("pad output is canonical");
            assert_eq!(back.expose(), &plaintext[..]);
            for edit in edits.iter().take(4) {
                match edit {
                    Edit::Xor { offset, value } => {
                        if !bytes.is_empty() {
                            let i = *offset as usize % bytes.len();
                            bytes[i] ^= value;
                        }
                    }
                    Edit::Truncate { len } => {
                        bytes.truncate(*len as usize % (bytes.len() + 1));
                    }
                    Edit::Extend { extra } => bytes.extend(extra.iter().take(32)),
                    Edit::AppendBlocks { n } => {
                        let blocks = usize::from(*n % 4) + 1;
                        bytes.extend(std::iter::repeat_n(0u8, blocks * PAD_BLOCK));
                    }
                    Edit::DropBlock => {
                        if bytes.len() >= PAD_BLOCK {
                            bytes.truncate(bytes.len() - PAD_BLOCK);
                        }
                    }
                }
            }
            if let Ok(out) = unpad(&bytes) {
                let again = pad(out.expose()).expect("accepted input fits");
                assert_eq!(again.expose(), &bytes[..]);
            }
        }
    }
});
