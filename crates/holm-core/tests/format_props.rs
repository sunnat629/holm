//! Property tests for the header parser and the padding.
//!
//! Random bytes almost never start with the 8-byte magic, so they stop at the
//! first check and test nothing else. These tests build a valid file first and
//! then damage it, which reaches every later check.

use holm_core::format::{HEADER_LEN, Header};
use holm_core::padding::{PAD_BLOCK, pad, unpad};
use holm_crypto::kdf::{KdfParams, MAX_M_KIB, MAX_WORK};
use proptest::prelude::*;

/// A valid file: its header, the body bytes and the whole encoded file.
#[derive(Clone, Debug)]
struct ValidFile {
    header: Header,
    body: Vec<u8>,
    bytes: Vec<u8>,
}

fn valid_file() -> impl Strategy<Value = ValidFile> {
    (3u32..=16)
        .prop_flat_map(|iterations| {
            let max_m = u64::from(MAX_M_KIB).min(MAX_WORK / u64::from(iterations));
            let max_m = u32::try_from(max_m).expect("capped by MAX_M_KIB");
            (Just(iterations), 65_536u32..=max_m)
        })
        .prop_flat_map(|(iterations, memory_kib)| {
            (
                Just(KdfParams {
                    memory_kib,
                    iterations,
                    parallelism: 1,
                }),
                any::<[u8; 32]>(),
                any::<[u8; 24]>(),
                any::<[u8; 48]>(),
                any::<[u8; 24]>(),
                prop::collection::vec(any::<u8>(), 16..=64),
            )
        })
        .prop_map(|(kdf, salt, wrap_nonce, wrapped_dek, body_nonce, body)| {
            let header = Header {
                kdf,
                salt,
                wrap_nonce,
                wrapped_dek,
                body_nonce,
                body_len: body.len() as u64,
            };
            let mut bytes = header.encode().to_vec();
            bytes.extend_from_slice(&body);
            ValidFile {
                header,
                body,
                bytes,
            }
        })
}

/// One damaging step applied to a byte buffer.
#[derive(Clone, Debug)]
enum Edit {
    Overwrite { offset: usize, value: u8 },
    Truncate { len: usize },
    Extend { extra: Vec<u8> },
}

fn edit() -> impl Strategy<Value = Edit> {
    prop_oneof![
        (any::<usize>(), any::<u8>()).prop_map(|(offset, value)| Edit::Overwrite { offset, value }),
        any::<usize>().prop_map(|len| Edit::Truncate { len }),
        prop::collection::vec(any::<u8>(), 1..32).prop_map(|extra| Edit::Extend { extra }),
    ]
}

fn apply(bytes: &mut Vec<u8>, edits: &[Edit]) {
    for e in edits {
        match e {
            Edit::Overwrite { offset, value } => {
                if !bytes.is_empty() {
                    let i = offset % bytes.len();
                    bytes[i] = *value;
                }
            }
            Edit::Truncate { len } => bytes.truncate(len % (bytes.len() + 1)),
            Edit::Extend { extra } => bytes.extend_from_slice(extra),
        }
    }
}

/// Parse must not panic. If it accepts, the header must re-encode to the input.
fn check_parse(bytes: &[u8]) -> Result<(), TestCaseError> {
    if let Ok((header, body)) = Header::parse(bytes) {
        prop_assert_eq!(&header.encode()[..], &bytes[..HEADER_LEN]);
        prop_assert_eq!(body, &bytes[HEADER_LEN..]);
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn encode_parse_roundtrip(f in valid_file()) {
        let (header, body) = Header::parse(&f.bytes).expect("a generated file is valid");
        prop_assert_eq!(&header, &f.header);
        prop_assert_eq!(header.kdf.parallelism, 1);
        prop_assert_eq!(header.body_len, f.body.len() as u64);
        prop_assert_eq!(body, &f.body[..]);
    }

    #[test]
    fn parse_never_panics_on_mutations(
        f in valid_file(),
        edits in prop::collection::vec(edit(), 1..=4),
    ) {
        let mut bytes = f.bytes;
        apply(&mut bytes, &edits);
        check_parse(&bytes)?;
    }

    #[test]
    fn parse_never_panics_on_random(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        check_parse(&bytes)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn pad_unpad_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..40_000)) {
        let padded = pad(&plaintext).expect("small input");
        prop_assert_eq!(padded.len() % PAD_BLOCK, 0);
        let back = unpad(padded.expose()).expect("pad output is canonical");
        prop_assert_eq!(back.expose(), &plaintext[..]);
    }

    #[test]
    fn unpad_never_panics(
        plaintext in prop::collection::vec(any::<u8>(), 0..40_000),
        edits in prop::collection::vec(edit(), 0..=4),
        random in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut bytes = pad(&plaintext).expect("small input").expose().to_vec();
        apply(&mut bytes, &edits);
        // Any result is fine, as long as there is no panic. An accepted buffer must
        // be the canonical padding of what it returns.
        if let Ok(out) = unpad(&bytes) {
            let again = pad(out.expose()).expect("fits");
            prop_assert_eq!(again.expose(), &bytes[..]);
        }
        let _ = unpad(&random);
    }
}

/// Writes the fuzz seed. Run once: `cargo test -p holm-core --test format_props -- --ignored`
#[test]
#[ignore = "writes fuzz/seeds/parse_header/valid_floor; run once and commit the file"]
fn write_seed_corpus() {
    let header = Header {
        kdf: KdfParams::FLOOR,
        salt: [1; 32],
        wrap_nonce: [2; 24],
        wrapped_dek: [3; 48],
        body_nonce: [4; 24],
        body_len: 16,
    };
    let mut bytes = header.encode().to_vec();
    bytes.extend_from_slice(&[9; 16]);
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/parse_header");
    std::fs::create_dir_all(&dir).expect("create seed dir");
    std::fs::write(dir.join("valid_floor"), &bytes).expect("write seed");
}
