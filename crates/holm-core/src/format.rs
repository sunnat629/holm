//! The v1 vault header: exact byte layout, strict parser, serializer.
//!
//! The parser reads bytes an attacker may have written. It never panics: every
//! read goes through `get` or a checked operation, and every failure is a
//! distinct [`FormatError`] that carries no secret. Checks run cheapest first,
//! and the KDF cost policy runs before anyone derives a key, so a hostile
//! header cannot make us allocate a gigabyte or hash for minutes.
//!
//! Layout (offset/size, little-endian): magic 0/8, version 8/2, flags 10/2,
//! kdf id 12/1, reserved 13/3, memory KiB 16/4, iterations 20/4, parallelism
//! 24/4, salt 28/32, wrap nonce 60/24, wrapped DEK 84/48, body nonce 132/24,
//! body length 156/8, then the body ciphertext.
//!
//! The wrap AAD is bytes `0..60` ([`WRAP_AAD_LEN`]); the body AAD is bytes
//! `0..164` ([`HEADER_LEN`]).

use holm_crypto::KdfParamsError;
use holm_crypto::aead::TAG_LEN;
use holm_crypto::kdf::KdfParams;

/// The eight magic bytes that start every vault file.
pub const MAGIC: [u8; 8] = *b"HOLMVLT\0";
/// The only format version this code reads and writes.
pub const FORMAT_VERSION: u16 = 1;
/// KDF id for Argon2id version 1.3.
pub const KDF_ID_ARGON2ID: u8 = 1;
/// Header length in bytes.
pub const HEADER_LEN: usize = 164;
/// Length of the prefix that authenticates the wrapped key (bytes `0..60`).
pub const WRAP_AAD_LEN: usize = 60;
/// Largest vault file accepted, in bytes (64 MiB).
pub const MAX_FILE_LEN: usize = 67_108_864;

// Field offsets. Kept together so the layout is written down once.
const OFF_VERSION: usize = 8;
const OFF_FLAGS: usize = 10;
const OFF_KDF_ID: usize = 12;
const OFF_RESERVED: usize = 13;
const OFF_MEMORY: usize = 16;
const OFF_ITERATIONS: usize = 20;
const OFF_PARALLELISM: usize = 24;
const OFF_SALT: usize = 28;
const OFF_WRAP_NONCE: usize = 60;
const OFF_WRAPPED_DEK: usize = 84;
const OFF_BODY_NONCE: usize = 132;
const OFF_BODY_LEN: usize = 156;

// A typo in the table above fails the build instead of silently moving a field.
const _: () = {
    assert!(OFF_RESERVED + 3 == OFF_MEMORY);
    assert!(OFF_PARALLELISM + 4 == OFF_SALT);
    assert!(OFF_SALT + 32 == OFF_WRAP_NONCE);
    assert!(OFF_WRAP_NONCE == WRAP_AAD_LEN);
    assert!(OFF_WRAP_NONCE + 24 == OFF_WRAPPED_DEK);
    assert!(OFF_WRAPPED_DEK + 48 == OFF_BODY_NONCE);
    assert!(OFF_BODY_NONCE + 24 == OFF_BODY_LEN);
    assert!(OFF_BODY_LEN + 8 == HEADER_LEN);
};

/// Why a vault file was refused. No variant holds file contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    /// The file is larger than [`MAX_FILE_LEN`].
    #[error("vault file is too large")]
    TooLarge,
    /// The file is shorter than a header.
    #[error("vault file is too short to hold a header")]
    TooShort,
    /// The file does not start with the Holm magic bytes.
    #[error("not a Holm vault file")]
    BadMagic,
    /// The format version is not one this build can read.
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),
    /// A flag bit is set. v1 defines no flags.
    #[error("unknown flags are set")]
    BadFlags,
    /// The KDF id is not Argon2id.
    #[error("unknown KDF id {0}")]
    UnknownKdf(u8),
    /// A reserved byte is not zero.
    #[error("reserved header bytes are not zero")]
    ReservedNotZero,
    /// The key-derivation costs break Holm's policy.
    #[error("key-derivation costs refused: {0}")]
    KdfPolicy(KdfParamsError),
    /// The body length field does not match the bytes in the file.
    #[error("body length does not match the file size")]
    LengthMismatch,
    /// The body is too short to hold an authentication tag.
    #[error("body is too short to hold an authentication tag")]
    BodyTooShort,
}

/// A parsed vault header. The data key appears only in wrapped form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Argon2id costs.
    pub kdf: KdfParams,
    /// Argon2id salt.
    pub salt: [u8; 32],
    /// Nonce used to wrap the data key.
    pub wrap_nonce: [u8; 24],
    /// The data key, encrypted (32 bytes plus a 16-byte tag).
    pub wrapped_dek: [u8; 48],
    /// Nonce used to encrypt the body.
    pub body_nonce: [u8; 24],
    /// Length of the body ciphertext in bytes, tag included.
    pub body_len: u64,
}

/// Copies `N` bytes starting at `offset`, or `None` if they are not all there.
fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    bytes.get(offset..end)?.try_into().ok()
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    read_array(bytes, offset).map(u16::from_le_bytes)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    read_array(bytes, offset).map(u32::from_le_bytes)
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    read_array(bytes, offset).map(u64::from_le_bytes)
}

fn put(out: &mut [u8; HEADER_LEN], offset: usize, bytes: &[u8]) {
    // Offsets are the constants above, so the range is always inside the
    // array. `get_mut` keeps even a future typo from panicking.
    if let Some(dst) = offset
        .checked_add(bytes.len())
        .and_then(|end| out.get_mut(offset..end))
    {
        dst.copy_from_slice(bytes);
    }
}

impl Header {
    /// Serializes the header to its 164 bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        put(&mut out, 0, &MAGIC);
        put(&mut out, OFF_VERSION, &FORMAT_VERSION.to_le_bytes());
        // Flags (10..12) and reserved (13..16) stay zero.
        put(&mut out, OFF_KDF_ID, &[KDF_ID_ARGON2ID]);
        put(&mut out, OFF_MEMORY, &self.kdf.memory_kib.to_le_bytes());
        put(&mut out, OFF_ITERATIONS, &self.kdf.iterations.to_le_bytes());
        put(
            &mut out,
            OFF_PARALLELISM,
            &self.kdf.parallelism.to_le_bytes(),
        );
        put(&mut out, OFF_SALT, &self.salt);
        put(&mut out, OFF_WRAP_NONCE, &self.wrap_nonce);
        put(&mut out, OFF_WRAPPED_DEK, &self.wrapped_dek);
        put(&mut out, OFF_BODY_NONCE, &self.body_nonce);
        put(&mut out, OFF_BODY_LEN, &self.body_len.to_le_bytes());
        out
    }

    /// Parses a whole vault file and returns the header and the body
    /// ciphertext, which borrows from `file`.
    ///
    /// Checks run in this order: file size, magic, version, flags, KDF id,
    /// reserved bytes, KDF cost policy, body tag room, exact total length.
    /// Nothing is derived or decrypted here.
    ///
    /// # Errors
    /// Returns the [`FormatError`] for the first check that fails.
    pub fn parse(file: &[u8]) -> Result<(Header, &[u8]), FormatError> {
        if file.len() > MAX_FILE_LEN {
            return Err(FormatError::TooLarge);
        }
        let head = file.get(..HEADER_LEN).ok_or(FormatError::TooShort)?;
        let body = file.get(HEADER_LEN..).ok_or(FormatError::TooShort)?;

        if head.get(..MAGIC.len()) != Some(&MAGIC[..]) {
            return Err(FormatError::BadMagic);
        }
        let version = read_u16(head, OFF_VERSION).ok_or(FormatError::TooShort)?;
        if version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }
        if read_u16(head, OFF_FLAGS).ok_or(FormatError::TooShort)? != 0 {
            return Err(FormatError::BadFlags);
        }
        let [kdf_id] = read_array::<1>(head, OFF_KDF_ID).ok_or(FormatError::TooShort)?;
        if kdf_id != KDF_ID_ARGON2ID {
            return Err(FormatError::UnknownKdf(kdf_id));
        }
        let reserved = read_array::<3>(head, OFF_RESERVED).ok_or(FormatError::TooShort)?;
        if reserved != [0; 3] {
            return Err(FormatError::ReservedNotZero);
        }

        let kdf = KdfParams {
            memory_kib: read_u32(head, OFF_MEMORY).ok_or(FormatError::TooShort)?,
            iterations: read_u32(head, OFF_ITERATIONS).ok_or(FormatError::TooShort)?,
            parallelism: read_u32(head, OFF_PARALLELISM).ok_or(FormatError::TooShort)?,
        };
        kdf.validate().map_err(FormatError::KdfPolicy)?;

        let body_len = read_u64(head, OFF_BODY_LEN).ok_or(FormatError::TooShort)?;
        let body_len_usize = usize::try_from(body_len).map_err(|_| FormatError::LengthMismatch)?;
        if body_len_usize < TAG_LEN {
            return Err(FormatError::BodyTooShort);
        }
        let total = HEADER_LEN
            .checked_add(body_len_usize)
            .ok_or(FormatError::LengthMismatch)?;
        if total != file.len() {
            return Err(FormatError::LengthMismatch);
        }

        let header = Header {
            kdf,
            salt: read_array(head, OFF_SALT).ok_or(FormatError::TooShort)?,
            wrap_nonce: read_array(head, OFF_WRAP_NONCE).ok_or(FormatError::TooShort)?,
            wrapped_dek: read_array(head, OFF_WRAPPED_DEK).ok_or(FormatError::TooShort)?,
            body_nonce: read_array(head, OFF_BODY_NONCE).ok_or(FormatError::TooShort)?,
            body_len,
        };
        Ok((header, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use holm_crypto::kdf::KdfParams;

    fn valid_header() -> Header {
        Header {
            kdf: KdfParams::FLOOR,
            salt: [1; 32],
            wrap_nonce: [2; 24],
            wrapped_dek: [3; 48],
            body_nonce: [4; 24],
            body_len: 16,
        }
    }

    fn file(h: &Header, body: &[u8]) -> Vec<u8> {
        let mut v = h.encode().to_vec();
        v.extend_from_slice(body);
        v
    }

    fn valid_file() -> Vec<u8> {
        file(&valid_header(), &[9; 16])
    }

    fn parse_err(bytes: &[u8]) -> FormatError {
        Header::parse(bytes).expect_err("must be rejected")
    }

    fn with_byte(index: usize, value: u8) -> Vec<u8> {
        let mut f = valid_file();
        f[index] = value;
        f
    }

    fn with_u32(offset: usize, value: u32) -> Vec<u8> {
        let mut f = valid_file();
        f[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        f
    }

    fn with_body_len(value: u64) -> Vec<u8> {
        let mut f = valid_file();
        f[OFF_BODY_LEN..OFF_BODY_LEN + 8].copy_from_slice(&value.to_le_bytes());
        f
    }

    #[test]
    fn encode_then_parse_roundtrip() {
        let h = valid_header();
        let body = [9u8; 16];
        let bytes = file(&h, &body);
        let (parsed, got_body) = Header::parse(&bytes).unwrap();
        assert_eq!(parsed, h);
        assert_eq!(got_body, &body[..]);
        assert_eq!(parsed.encode(), h.encode());
    }

    #[test]
    fn kdf_params_round_trip_exactly() {
        let mut h = valid_header();
        h.kdf = KdfParams {
            memory_kib: 131_072,
            iterations: 4,
            parallelism: 1,
        };
        let bytes = h.encode();
        assert_eq!(&bytes[16..20], &131_072u32.to_le_bytes());
        assert_eq!(&bytes[20..24], &4u32.to_le_bytes());
        assert_eq!(&bytes[24..28], &1u32.to_le_bytes());
        let (parsed, _) = Header::parse(&file(&h, &[0; 16])).unwrap();
        assert_eq!(parsed.kdf, h.kdf);
    }

    #[test]
    fn encoded_length_is_164() {
        assert_eq!(valid_header().encode().len(), 164);
        assert_eq!(HEADER_LEN, 164);
    }

    #[test]
    fn wrap_aad_is_first_60_bytes() {
        let a = valid_header();
        let mut b = a.clone();
        b.wrap_nonce = [0xAA; 24];
        b.wrapped_dek = [0xBB; 48];
        b.body_nonce = [0xCC; 24];
        b.body_len = 999;
        assert_eq!(a.encode()[..WRAP_AAD_LEN], b.encode()[..WRAP_AAD_LEN]);
        assert_ne!(a.encode()[WRAP_AAD_LEN..], b.encode()[WRAP_AAD_LEN..]);
        // The salt and KDF costs are inside the authenticated prefix.
        let mut c = a.clone();
        c.salt = [0xDD; 32];
        assert_ne!(a.encode()[..WRAP_AAD_LEN], c.encode()[..WRAP_AAD_LEN]);
    }

    #[test]
    fn too_large_rejected() {
        let f = vec![0u8; MAX_FILE_LEN + 1];
        assert_eq!(parse_err(&f), FormatError::TooLarge);
    }

    #[test]
    fn too_short_rejected() {
        assert_eq!(parse_err(&[]), FormatError::TooShort);
    }

    #[test]
    fn truncated_header_rejected_at_every_length() {
        let f = valid_file();
        for len in 0..HEADER_LEN {
            assert_eq!(parse_err(&f[..len]), FormatError::TooShort, "len {len}");
        }
    }

    #[test]
    fn bad_magic_rejected() {
        assert_eq!(parse_err(&with_byte(0, b'X')), FormatError::BadMagic);
        assert_eq!(parse_err(&with_byte(7, 1)), FormatError::BadMagic);
    }

    #[test]
    fn unsupported_version_rejected() {
        assert_eq!(
            parse_err(&with_byte(8, 2)),
            FormatError::UnsupportedVersion(2)
        );
        assert_eq!(
            parse_err(&with_byte(9, 1)),
            FormatError::UnsupportedVersion(257)
        );
        assert_eq!(
            parse_err(&with_byte(8, 0)),
            FormatError::UnsupportedVersion(0)
        );
    }

    #[test]
    fn bad_flags_rejected() {
        assert_eq!(parse_err(&with_byte(10, 1)), FormatError::BadFlags);
        assert_eq!(parse_err(&with_byte(11, 0x80)), FormatError::BadFlags);
    }

    #[test]
    fn unknown_kdf_rejected() {
        assert_eq!(parse_err(&with_byte(12, 2)), FormatError::UnknownKdf(2));
        assert_eq!(parse_err(&with_byte(12, 0)), FormatError::UnknownKdf(0));
    }

    #[test]
    fn reserved_not_zero_rejected() {
        for i in 13..16 {
            assert_eq!(parse_err(&with_byte(i, 1)), FormatError::ReservedNotZero);
        }
    }

    #[test]
    fn kdf_below_floor_rejected() {
        assert_eq!(
            parse_err(&with_u32(OFF_MEMORY, 65_535)),
            FormatError::KdfPolicy(KdfParamsError::BelowFloor)
        );
        assert_eq!(
            parse_err(&with_u32(OFF_ITERATIONS, 2)),
            FormatError::KdfPolicy(KdfParamsError::BelowFloor)
        );
    }

    #[test]
    fn kdf_parallelism_rejected() {
        assert_eq!(
            parse_err(&with_u32(OFF_PARALLELISM, 2)),
            FormatError::KdfPolicy(KdfParamsError::UnsupportedParallelism)
        );
    }

    #[test]
    fn kdf_caps_enforced_in_parse() {
        assert_eq!(
            parse_err(&with_u32(OFF_MEMORY, 2_097_152)),
            FormatError::KdfPolicy(KdfParamsError::AboveCeiling)
        );
        let mut f = with_u32(OFF_MEMORY, 1_048_576);
        f[OFF_ITERATIONS..OFF_ITERATIONS + 4].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(
            parse_err(&f),
            FormatError::KdfPolicy(KdfParamsError::TooMuchWork)
        );
    }

    #[test]
    fn body_shorter_than_tag_rejected() {
        let mut f = file(&valid_header(), &[0; 15]);
        f[OFF_BODY_LEN..OFF_BODY_LEN + 8].copy_from_slice(&15u64.to_le_bytes());
        assert_eq!(parse_err(&f), FormatError::BodyTooShort);
    }

    #[test]
    fn body_len_15_with_16_bytes_present() {
        assert_eq!(parse_err(&with_body_len(15)), FormatError::BodyTooShort);
    }

    #[test]
    fn trailing_byte_rejected() {
        let mut f = valid_file();
        f.push(0);
        assert_eq!(parse_err(&f), FormatError::LengthMismatch);
    }

    #[test]
    fn truncated_body_rejected() {
        let mut f = valid_file();
        f[OFF_BODY_LEN..OFF_BODY_LEN + 8].copy_from_slice(&1000u64.to_le_bytes());
        assert_eq!(parse_err(&f), FormatError::LengthMismatch);
    }

    #[test]
    fn body_len_u64_max_rejected_without_panic() {
        assert_eq!(
            parse_err(&with_body_len(u64::MAX)),
            FormatError::LengthMismatch
        );
        assert_eq!(
            parse_err(&with_body_len(u64::MAX - 163)),
            FormatError::LengthMismatch
        );
    }

    #[test]
    fn file_of_exactly_max_len_passes_size_check() {
        let mut h = valid_header();
        let body_len = MAX_FILE_LEN - HEADER_LEN;
        h.body_len = u64::try_from(body_len).unwrap();
        let mut f = h.encode().to_vec();
        f.resize(MAX_FILE_LEN, 0);
        let (parsed, body) = Header::parse(&f).unwrap();
        assert_eq!(parsed, h);
        assert_eq!(body.len(), body_len);
    }

    #[test]
    fn file_one_over_max_rejected() {
        let mut h = valid_header();
        h.body_len = u64::try_from(MAX_FILE_LEN + 1 - HEADER_LEN).unwrap();
        let mut f = h.encode().to_vec();
        f.resize(MAX_FILE_LEN + 1, 0);
        assert_eq!(parse_err(&f), FormatError::TooLarge);
    }

    #[test]
    fn errors_have_distinct_messages() {
        let all = [
            FormatError::TooLarge,
            FormatError::TooShort,
            FormatError::BadMagic,
            FormatError::UnsupportedVersion(2),
            FormatError::BadFlags,
            FormatError::UnknownKdf(2),
            FormatError::ReservedNotZero,
            FormatError::KdfPolicy(KdfParamsError::BelowFloor),
            FormatError::LengthMismatch,
            FormatError::BodyTooShort,
        ];
        let mut seen = std::collections::HashSet::new();
        for e in &all {
            assert!(seen.insert(e.to_string()), "duplicate message: {e}");
        }
    }

    // Hand-written bytes of a header whose fields all differ, byte by byte.
    // Layout: magic, version 1, flags 0, kdf id 1, reserved 0, memory 131072,
    // iterations 4, parallelism 1, salt 0x00.., wrap nonce 0x20.., wrapped
    // DEK 0x40.., body nonce 0x80.., body_len 0x120. Written without using
    // `encode`, so a shared offset or byte-order bug cannot hide.
    #[rustfmt::skip]
    const GOLDEN: [u8; HEADER_LEN] = [
        0x48, 0x4f, 0x4c, 0x4d, 0x56, 0x4c, 0x54, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
        0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63,
        0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
        0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    fn golden_header() -> Header {
        Header {
            kdf: KdfParams {
                memory_kib: 131_072,
                iterations: 4,
                parallelism: 1,
            },
            salt: core::array::from_fn(|i| u8::try_from(i).unwrap()),
            wrap_nonce: core::array::from_fn(|i| 0x20 + u8::try_from(i).unwrap()),
            wrapped_dek: core::array::from_fn(|i| 0x40 + u8::try_from(i).unwrap()),
            body_nonce: core::array::from_fn(|i| 0x80 + u8::try_from(i).unwrap()),
            body_len: 0x120,
        }
    }

    #[test]
    fn golden_bytes_encode() {
        assert_eq!(golden_header().encode(), GOLDEN);
    }

    #[test]
    fn golden_bytes_parse() {
        let mut f = GOLDEN.to_vec();
        f.extend_from_slice(&[7; 0x120]);
        let (h, body) = Header::parse(&f).unwrap();
        assert_eq!(h, golden_header());
        assert_eq!(body, &[7; 0x120][..]);
    }

    #[test]
    fn truncation_inside_body_rejected() {
        let f = valid_file();
        for len in HEADER_LEN..f.len() {
            assert_eq!(
                parse_err(&f[..len]),
                FormatError::LengthMismatch,
                "len {len}"
            );
        }
    }

    #[test]
    fn kdf_policy_is_reported_before_length_faults() {
        let mut f = with_u32(OFF_MEMORY, 65_535);
        f.push(0); // trailing byte too
        assert_eq!(
            parse_err(&f),
            FormatError::KdfPolicy(KdfParamsError::BelowFloor)
        );
    }
}
