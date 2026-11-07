//! Property tests for the header parser and the padding.
//!
//! Random bytes almost never start with the 8-byte magic, so they stop at the
//! first check and test nothing else. These tests build a valid file first and
//! then damage it, which reaches every later check.

use holm_core::format::{HEADER_LEN, HEADER_LEN_V2, Header, HeaderV2, ParsedHeader, parse_any};
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
    Overwrite {
        offset: usize,
        value: u8,
    },
    Truncate {
        len: usize,
    },
    Extend {
        extra: Vec<u8>,
    },
    /// Whole zero blocks, so `unpad` sees a buffer longer than the body needs.
    AppendBlocks {
        n: usize,
    },
}

fn edit() -> impl Strategy<Value = Edit> {
    prop_oneof![
        (any::<usize>(), any::<u8>()).prop_map(|(offset, value)| Edit::Overwrite { offset, value }),
        any::<usize>().prop_map(|len| Edit::Truncate { len }),
        prop::collection::vec(any::<u8>(), 1..32).prop_map(|extra| Edit::Extend { extra }),
        (1usize..=3).prop_map(|n| Edit::AppendBlocks { n }),
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
            Edit::AppendBlocks { n } => bytes.extend(std::iter::repeat_n(0u8, n * PAD_BLOCK)),
        }
    }
}

/// Plaintext lengths: mostly random, often right at a block boundary.
fn plaintext_near_blocks() -> impl Strategy<Value = Vec<u8>> {
    let edge = prop_oneof![
        Just(0usize),
        Just(PAD_BLOCK - 5),
        Just(PAD_BLOCK - 4),
        Just(PAD_BLOCK - 3),
        Just(2 * PAD_BLOCK - 5),
        Just(2 * PAD_BLOCK - 4),
        Just(2 * PAD_BLOCK - 3),
    ];
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..40_000),
        edge.prop_flat_map(|n| prop::collection::vec(any::<u8>(), n..=n)),
    ]
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

/// A valid v2 file: random key block fields, an index of 1..=2 blocks and a records
/// region of 0..=2 blocks, all with the exact framing the parser demands.
fn valid_v2_file() -> impl Strategy<Value = (HeaderV2, Vec<u8>)> {
    (
        (3u32..=16).prop_flat_map(|iterations| {
            let max_m = u64::from(MAX_M_KIB).min(MAX_WORK / u64::from(iterations));
            let max_m = u32::try_from(max_m).expect("capped by MAX_M_KIB");
            (Just(iterations), 65_536u32..=max_m)
        }),
        any::<[u8; 32]>(),
        any::<[u8; 24]>(),
        any::<[u8; 48]>(),
        any::<[u8; 24]>(),
        1usize..=2,
        0usize..=2,
        any::<u8>(),
    )
        .prop_map(
            |(
                (iterations, memory_kib),
                salt,
                wrap_nonce,
                wrapped_dek,
                index_nonce,
                ib,
                rb,
                fill,
            )| {
                let index_len = ib * PAD_BLOCK + 16;
                let records_len = rb * PAD_BLOCK;
                let header = HeaderV2 {
                    kdf: KdfParams {
                        memory_kib,
                        iterations,
                        parallelism: 1,
                    },
                    salt,
                    wrap_nonce,
                    wrapped_dek,
                    index_nonce,
                    index_len: index_len as u64,
                    records_len: records_len as u64,
                };
                let mut bytes = header.encode().to_vec();
                bytes.extend(std::iter::repeat_n(fill, index_len + records_len));
                (header, bytes)
            },
        )
}

/// `parse_any` must not panic. If it accepts, the header must re-encode to the input
/// and the slices must add up to the file.
fn check_parse_any(bytes: &[u8]) -> Result<(), TestCaseError> {
    match parse_any(bytes) {
        Ok(ParsedHeader::V1(header, body)) => {
            prop_assert_eq!(&header.encode()[..], &bytes[..HEADER_LEN]);
            prop_assert_eq!(body, &bytes[HEADER_LEN..]);
        }
        Ok(ParsedHeader::V2(header, index, records)) => {
            prop_assert_eq!(&header.encode()[..], &bytes[..HEADER_LEN_V2]);
            prop_assert_eq!(HEADER_LEN_V2 + index.len() + records.len(), bytes.len());
            prop_assert_eq!(index.len() as u64, header.index_len);
            prop_assert_eq!(records.len() as u64, header.records_len);
        }
        Err(_) => {}
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn parse_any_never_panics(
        (_, v2) in valid_v2_file(),
        v1 in valid_file(),
        edits in prop::collection::vec(edit(), 0..=4),
        pick_v1 in any::<bool>(),
        random in prop::collection::vec(any::<u8>(), 0..400),
    ) {
        let mut bytes = if pick_v1 { v1.bytes } else { v2 };
        apply(&mut bytes, &edits);
        check_parse_any(&bytes)?;
        check_parse_any(&random)?;
    }

    #[test]
    fn v2_accepted_reencodes_identical((header, bytes) in valid_v2_file()) {
        match parse_any(&bytes) {
            Ok(ParsedHeader::V2(parsed, index, records)) => {
                prop_assert_eq!(&parsed, &header);
                prop_assert_eq!(&parsed.encode()[..], &bytes[..HEADER_LEN_V2]);
                prop_assert_eq!(index.len() as u64, header.index_len);
                prop_assert_eq!(records.len() as u64, header.records_len);
            }
            other => prop_assert!(false, "valid v2 file refused: {other:?}"),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn pad_unpad_roundtrip(plaintext in plaintext_near_blocks()) {
        let padded = pad(&plaintext).expect("small input");
        prop_assert_eq!(padded.len() % PAD_BLOCK, 0);
        let back = unpad(padded.expose()).expect("pad output is canonical");
        prop_assert_eq!(back.expose(), &plaintext[..]);
    }

    #[test]
    fn unpad_never_panics(
        plaintext in plaintext_near_blocks(),
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

/// A canonical buffer plus extra whole zero blocks is a second padded form of the same
/// body. `unpad` must refuse it, and must refuse a canonical buffer minus a block.
#[test]
fn extra_or_missing_blocks_are_rejected() {
    for len in (0..40_000usize).step_by(997).chain([
        0,
        PAD_BLOCK - 5,
        PAD_BLOCK - 4,
        PAD_BLOCK - 3,
        2 * PAD_BLOCK - 4,
    ]) {
        let plaintext = vec![0xAB; len];
        let padded = pad(&plaintext).expect("small input").expose().to_vec();
        assert!(unpad(&padded).is_ok(), "len {len}: canonical form accepted");
        for k in 1..=3 {
            let mut longer = padded.clone();
            longer.extend(std::iter::repeat_n(0u8, k * PAD_BLOCK));
            assert!(
                unpad(&longer).is_err(),
                "len {len}: {k} extra blocks accepted"
            );
        }
        if padded.len() > PAD_BLOCK {
            let shorter = &padded[..padded.len() - PAD_BLOCK];
            assert!(
                unpad(shorter).is_err(),
                "len {len}: one block fewer accepted"
            );
        }
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
