//! The vault header (formats v1 and v2): exact byte layout, strict parser, serializer.
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
//!
//! Format v2 keeps bytes `0..132` (the key block: everything up to and including
//! the wrapped DEK) and replaces the rest: index nonce 132/24, index ciphertext
//! length 156/8, records length 164/8, header total 172 ([`HEADER_LEN_V2`]).
//! Then come the index ciphertext and the records region. The index AAD is
//! bytes `0..172`. [`Header::parse`] reads v1 only; [`parse_any`] reads both.

use holm_crypto::KdfParamsError;
use holm_crypto::aead::TAG_LEN;
use holm_crypto::kdf::KdfParams;

use crate::padding::PAD_BLOCK;

/// The eight magic bytes that start every vault file.
pub const MAGIC: [u8; 8] = *b"HOLMVLT\0";
/// The format version this code writes. Until the session moves to format v2
/// it stays 1; [`Header::parse`] compares against [`FORMAT_V1`] either way.
pub const FORMAT_VERSION: u16 = 1;
/// Format version 1: header and one sealed body.
pub const FORMAT_V1: u16 = 1;
/// Format version 2: header, sealed index, per-item sealed records.
pub const FORMAT_V2: u16 = 2;
/// KDF id for Argon2id version 1.3.
pub const KDF_ID_ARGON2ID: u8 = 1;
/// Header length in bytes.
pub const HEADER_LEN: usize = 164;
/// Format v2 header length in bytes.
pub const HEADER_LEN_V2: usize = 172;
/// Length of the key block: bytes `0..132`, shared by v1 and v2. It is bound
/// into every record's AAD.
pub const KEY_BLOCK_LEN: usize = 132;
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
// v2 only: bytes 132.. replace the v1 body nonce and body length.
const OFF_INDEX_NONCE: usize = 132;
const OFF_INDEX_LEN: usize = 156;
const OFF_RECORDS_LEN: usize = 164;

// A typo in the table above fails the build instead of silently moving a field.
const _: () = {
    assert!(MAGIC.len() == OFF_VERSION);
    assert!(OFF_VERSION + 2 == OFF_FLAGS);
    assert!(OFF_FLAGS + 2 == OFF_KDF_ID);
    assert!(OFF_KDF_ID + 1 == OFF_RESERVED);
    assert!(OFF_RESERVED + 3 == OFF_MEMORY);
    assert!(OFF_MEMORY + 4 == OFF_ITERATIONS);
    assert!(OFF_ITERATIONS + 4 == OFF_PARALLELISM);
    assert!(OFF_PARALLELISM + 4 == OFF_SALT);
    assert!(OFF_SALT + 32 == OFF_WRAP_NONCE);
    assert!(OFF_WRAP_NONCE == WRAP_AAD_LEN);
    assert!(OFF_WRAP_NONCE + 24 == OFF_WRAPPED_DEK);
    assert!(OFF_WRAPPED_DEK + 48 == OFF_BODY_NONCE);
    assert!(OFF_BODY_NONCE + 24 == OFF_BODY_LEN);
    assert!(OFF_BODY_LEN + 8 == HEADER_LEN);
    assert!(OFF_WRAPPED_DEK + 48 == KEY_BLOCK_LEN);
    assert!(OFF_INDEX_NONCE == KEY_BLOCK_LEN);
    assert!(OFF_INDEX_NONCE + 24 == OFF_INDEX_LEN);
    assert!(OFF_INDEX_LEN + 8 == OFF_RECORDS_LEN);
    assert!(OFF_RECORDS_LEN + 8 == HEADER_LEN_V2);
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
    #[error("unsupported vault format version {0}; a newer version of Holm may be needed")]
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
    /// v2: the index length is too short for one block and a tag, or is not a
    /// whole number of blocks plus a tag.
    #[error("index length is not valid")]
    IndexLength,
    /// v2: the records length is not a whole number of blocks, or (once the
    /// index is open) not the length the index calls for.
    #[error("records length is not valid")]
    RecordsLength,
    /// v2: the filler after the last record is not all zero.
    #[error("the filler after the records is not zero")]
    Filler,
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

fn put<const N: usize>(out: &mut [u8; N], offset: usize, bytes: &[u8]) {
    // Offsets are the constants above, so the range is always inside the
    // array. `get_mut` keeps even a future typo from panicking.
    if let Some(dst) = offset
        .checked_add(bytes.len())
        .and_then(|end| out.get_mut(offset..end))
    {
        dst.copy_from_slice(bytes);
    }
}

/// Writes bytes `0..132`: magic, `version`, zero flags, KDF fields, salt, wrap
/// nonce and wrapped DEK. Shared by v1 and v2 so the two cannot drift apart.
fn encode_key_block(
    version: u16,
    kdf: &KdfParams,
    salt: &[u8; 32],
    wrap_nonce: &[u8; 24],
    wrapped_dek: &[u8; 48],
) -> [u8; KEY_BLOCK_LEN] {
    let mut out = [0u8; KEY_BLOCK_LEN];
    put(&mut out, 0, &MAGIC);
    put(&mut out, OFF_VERSION, &version.to_le_bytes());
    // Flags (10..12) and reserved (13..16) stay zero.
    put(&mut out, OFF_KDF_ID, &[KDF_ID_ARGON2ID]);
    put(&mut out, OFF_MEMORY, &kdf.memory_kib.to_le_bytes());
    put(&mut out, OFF_ITERATIONS, &kdf.iterations.to_le_bytes());
    put(&mut out, OFF_PARALLELISM, &kdf.parallelism.to_le_bytes());
    put(&mut out, OFF_SALT, salt);
    put(&mut out, OFF_WRAP_NONCE, wrap_nonce);
    put(&mut out, OFF_WRAPPED_DEK, wrapped_dek);
    out
}

/// The fields of bytes `0..132` after the shared checks.
struct KeyBlock {
    kdf: KdfParams,
    salt: [u8; 32],
    wrap_nonce: [u8; 24],
    wrapped_dek: [u8; 48],
}

/// Checks flags, KDF id, reserved bytes and the KDF cost policy of a header
/// whose magic and version are already accepted, then reads the key fields.
/// Both versions run exactly these checks, in this order.
fn parse_key_block(head: &[u8]) -> Result<KeyBlock, FormatError> {
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
    Ok(KeyBlock {
        kdf,
        salt: read_array(head, OFF_SALT).ok_or(FormatError::TooShort)?,
        wrap_nonce: read_array(head, OFF_WRAP_NONCE).ok_or(FormatError::TooShort)?,
        wrapped_dek: read_array(head, OFF_WRAPPED_DEK).ok_or(FormatError::TooShort)?,
    })
}

impl Header {
    /// Serializes the header to its 164 bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let kb = encode_key_block(
            FORMAT_VERSION,
            &self.kdf,
            &self.salt,
            &self.wrap_nonce,
            &self.wrapped_dek,
        );
        put(&mut out, 0, &kb);
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
        if version != FORMAT_V1 {
            return Err(FormatError::UnsupportedVersion(version));
        }
        let kb = parse_key_block(head)?;

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
            kdf: kb.kdf,
            salt: kb.salt,
            wrap_nonce: kb.wrap_nonce,
            wrapped_dek: kb.wrapped_dek,
            body_nonce: read_array(head, OFF_BODY_NONCE).ok_or(FormatError::TooShort)?,
            body_len,
        };
        Ok((header, body))
    }
}

/// A parsed v2 header. The data key appears only in wrapped form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderV2 {
    /// Argon2id costs.
    pub kdf: KdfParams,
    /// Argon2id salt.
    pub salt: [u8; 32],
    /// Nonce used to wrap the data key.
    pub wrap_nonce: [u8; 24],
    /// The data key, encrypted (32 bytes plus a 16-byte tag).
    pub wrapped_dek: [u8; 48],
    /// Nonce used to encrypt the index.
    pub index_nonce: [u8; 24],
    /// Length of the index ciphertext in bytes, tag included.
    pub index_len: u64,
    /// Length of the records region in bytes, filler included.
    pub records_len: u64,
}

impl HeaderV2 {
    /// Serializes the header to its 172 bytes (version 2).
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN_V2] {
        let mut out = [0u8; HEADER_LEN_V2];
        put(&mut out, 0, &self.key_block());
        put(&mut out, OFF_INDEX_NONCE, &self.index_nonce);
        put(&mut out, OFF_INDEX_LEN, &self.index_len.to_le_bytes());
        put(&mut out, OFF_RECORDS_LEN, &self.records_len.to_le_bytes());
        out
    }

    /// Bytes `0..132` as written in this header (version field 2). Bound into
    /// every record's AAD, so a record cannot move to another vault.
    #[must_use]
    pub fn key_block(&self) -> [u8; KEY_BLOCK_LEN] {
        encode_key_block(
            FORMAT_V2,
            &self.kdf,
            &self.salt,
            &self.wrap_nonce,
            &self.wrapped_dek,
        )
    }
}

/// A parsed header of either version, with the slices that follow it.
#[derive(Debug)]
pub enum ParsedHeader<'a> {
    /// Format v1: the header and the body ciphertext.
    V1(Header, &'a [u8]),
    /// Format v2: the header, the index ciphertext and the records region.
    V2(HeaderV2, &'a [u8], &'a [u8]),
}

/// Parses a whole vault file of format v1 or v2.
///
/// The key block (bytes `0..132`) is checked the same way for both. A version
/// other than 1 or 2 is [`FormatError::UnsupportedVersion`]. For v2 the
/// framing is exact: the index length is one or more [`PAD_BLOCK`]s plus a
/// tag, the records length is a multiple of [`PAD_BLOCK`], and header, index
/// and records add up to the file length (checked arithmetic). Nothing is
/// derived or decrypted here.
///
/// # Errors
/// Returns the [`FormatError`] for the first check that fails.
pub fn parse_any(file: &[u8]) -> Result<ParsedHeader<'_>, FormatError> {
    if file.len() > MAX_FILE_LEN {
        return Err(FormatError::TooLarge);
    }
    let head = file.get(..KEY_BLOCK_LEN).ok_or(FormatError::TooShort)?;
    if head.get(..MAGIC.len()) != Some(&MAGIC[..]) {
        return Err(FormatError::BadMagic);
    }
    match read_u16(head, OFF_VERSION).ok_or(FormatError::TooShort)? {
        FORMAT_V1 => Header::parse(file).map(|(h, body)| ParsedHeader::V1(h, body)),
        FORMAT_V2 => parse_v2(file),
        other => Err(FormatError::UnsupportedVersion(other)),
    }
}

fn parse_v2(file: &[u8]) -> Result<ParsedHeader<'_>, FormatError> {
    let head = file.get(..HEADER_LEN_V2).ok_or(FormatError::TooShort)?;
    let kb = parse_key_block(head)?;

    let index_len = read_u64(head, OFF_INDEX_LEN).ok_or(FormatError::TooShort)?;
    let records_len = read_u64(head, OFF_RECORDS_LEN).ok_or(FormatError::TooShort)?;
    let block = PAD_BLOCK as u64;
    let tag = TAG_LEN as u64;
    // At least one index block plus the tag, and block-aligned plaintext.
    match index_len.checked_sub(tag) {
        Some(pt) if pt >= block && pt % block == 0 => {}
        _ => return Err(FormatError::IndexLength),
    }
    if records_len % block != 0 {
        return Err(FormatError::RecordsLength);
    }
    let total = (HEADER_LEN_V2 as u64)
        .checked_add(index_len)
        .and_then(|n| n.checked_add(records_len))
        .ok_or(FormatError::LengthMismatch)?;
    if total != file.len() as u64 {
        return Err(FormatError::LengthMismatch);
    }
    // Lengths fit usize: they sum to file.len(), which is a usize.
    let index_end = usize::try_from(index_len)
        .ok()
        .and_then(|n| n.checked_add(HEADER_LEN_V2))
        .ok_or(FormatError::LengthMismatch)?;
    let index_ct = file
        .get(HEADER_LEN_V2..index_end)
        .ok_or(FormatError::LengthMismatch)?;
    let records = file.get(index_end..).ok_or(FormatError::LengthMismatch)?;

    let header = HeaderV2 {
        kdf: kb.kdf,
        salt: kb.salt,
        wrap_nonce: kb.wrap_nonce,
        wrapped_dek: kb.wrapped_dek,
        index_nonce: read_array(head, OFF_INDEX_NONCE).ok_or(FormatError::TooShort)?,
        index_len,
        records_len,
    };
    Ok(ParsedHeader::V2(header, index_ct, records))
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

    // ---- format v2 ----

    fn valid_header_v2() -> HeaderV2 {
        HeaderV2 {
            kdf: KdfParams::FLOOR,
            salt: [1; 32],
            wrap_nonce: [2; 24],
            wrapped_dek: [3; 48],
            index_nonce: [4; 24],
            index_len: (PAD_BLOCK + TAG_LEN) as u64,
            records_len: PAD_BLOCK as u64,
        }
    }

    fn file_v2(h: &HeaderV2) -> Vec<u8> {
        let mut v = h.encode().to_vec();
        v.resize(
            HEADER_LEN_V2 + usize::try_from(h.index_len + h.records_len).unwrap(),
            9,
        );
        v
    }

    fn valid_file_v2() -> Vec<u8> {
        file_v2(&valid_header_v2())
    }

    fn any_err(bytes: &[u8]) -> FormatError {
        parse_any(bytes).expect_err("must be rejected")
    }

    fn v2_with_lens(index_len: u64, records_len: u64) -> Vec<u8> {
        let mut f = valid_file_v2();
        f[OFF_INDEX_LEN..OFF_INDEX_LEN + 8].copy_from_slice(&index_len.to_le_bytes());
        f[OFF_RECORDS_LEN..OFF_RECORDS_LEN + 8].copy_from_slice(&records_len.to_le_bytes());
        f
    }

    // Hand-written: magic, version 2, flags 0, kdf id 1, reserved 0, memory
    // 131072, iterations 4, parallelism 1, salt 0x00.., wrap nonce 0x20..,
    // wrapped DEK 0x40.., index nonce 0x80.., index_len 0x4010 (16 KiB + tag),
    // records_len 0x8000. Written without `encode`.
    #[rustfmt::skip]
    const GOLDEN_V2: [u8; HEADER_LEN_V2] = [
        0x48, 0x4f, 0x4c, 0x4d, 0x56, 0x4c, 0x54, 0x00, 0x02, 0x00, 0x00, 0x00,
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
        0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    fn golden_header_v2() -> HeaderV2 {
        HeaderV2 {
            kdf: KdfParams {
                memory_kib: 131_072,
                iterations: 4,
                parallelism: 1,
            },
            salt: core::array::from_fn(|i| u8::try_from(i).unwrap()),
            wrap_nonce: core::array::from_fn(|i| 0x20 + u8::try_from(i).unwrap()),
            wrapped_dek: core::array::from_fn(|i| 0x40 + u8::try_from(i).unwrap()),
            index_nonce: core::array::from_fn(|i| 0x80 + u8::try_from(i).unwrap()),
            index_len: 0x4010,
            records_len: 0x8000,
        }
    }

    #[test]
    fn header_v2_golden() {
        assert_eq!(golden_header_v2().encode(), GOLDEN_V2);
        assert_eq!(HEADER_LEN_V2, 172);
        assert_eq!(
            golden_header_v2().key_block()[..],
            GOLDEN_V2[..KEY_BLOCK_LEN]
        );
        let mut f = GOLDEN_V2.to_vec();
        f.resize(HEADER_LEN_V2 + 0x4010 + 0x8000, 7);
        let ParsedHeader::V2(h, idx, rec) = parse_any(&f).unwrap() else {
            panic!("expected v2");
        };
        assert_eq!(h, golden_header_v2());
        assert_eq!((idx.len(), rec.len()), (0x4010, 0x8000));
    }

    #[test]
    fn header_v2_roundtrip() {
        let h = valid_header_v2();
        let f = file_v2(&h);
        let ParsedHeader::V2(got, idx, rec) = parse_any(&f).unwrap() else {
            panic!("expected v2");
        };
        assert_eq!(got, h);
        assert_eq!(got.encode(), h.encode());
        assert_eq!(idx.len(), PAD_BLOCK + TAG_LEN);
        assert_eq!(rec.len(), PAD_BLOCK);
        assert_eq!(idx.as_ptr(), f[HEADER_LEN_V2..].as_ptr());
    }

    #[test]
    fn parse_any_reads_v1_too() {
        let f = valid_file();
        let ParsedHeader::V1(h, body) = parse_any(&f).unwrap() else {
            panic!("expected v1");
        };
        assert_eq!(h, valid_header());
        assert_eq!(body.len(), 16);
    }

    #[test]
    fn v2_framing_exact_sum() {
        let mut f = valid_file_v2();
        f.push(0);
        assert_eq!(any_err(&f), FormatError::LengthMismatch);
        f.truncate(f.len() - 2);
        assert_eq!(any_err(&f), FormatError::LengthMismatch);
        // Header-only and short files.
        for len in 0..HEADER_LEN_V2 {
            assert_eq!(
                any_err(&valid_file_v2()[..len]),
                FormatError::TooShort,
                "len {len}"
            );
        }
    }

    #[test]
    fn v2_index_len_not_block_multiple() {
        let tag = TAG_LEN as u64;
        let b = PAD_BLOCK as u64;
        for bad in [
            0,
            tag - 1,
            tag,
            b,
            b + tag - 1,
            b + tag + 1,
            2 * b,
            2 * b + tag + 1,
        ] {
            assert_eq!(
                any_err(&v2_with_lens(bad, b)),
                FormatError::IndexLength,
                "index_len {bad}"
            );
        }
        // Two blocks plus tag is a valid length (framing then decides).
        assert_eq!(
            any_err(&v2_with_lens(2 * b + tag, b)),
            FormatError::LengthMismatch
        );
    }

    #[test]
    fn v2_records_len_not_block_multiple() {
        let idx = (PAD_BLOCK + TAG_LEN) as u64;
        for bad in [1, 255, PAD_BLOCK as u64 - 1, PAD_BLOCK as u64 + 1] {
            assert_eq!(
                any_err(&v2_with_lens(idx, bad)),
                FormatError::RecordsLength,
                "records_len {bad}"
            );
        }
        // Zero records is a valid empty region.
        let h = HeaderV2 {
            records_len: 0,
            ..valid_header_v2()
        };
        assert!(parse_any(&file_v2(&h)).is_ok());
    }

    #[test]
    fn v2_lengths_overflow_u64() {
        let b = PAD_BLOCK as u64;
        let tag = TAG_LEN as u64;
        let big_index = (u64::MAX - tag) / b * b + tag;
        let big_records = u64::MAX / b * b;
        assert_eq!(
            any_err(&v2_with_lens(big_index, big_records)),
            FormatError::LengthMismatch
        );
        assert_eq!(
            any_err(&v2_with_lens(big_index, b)),
            FormatError::LengthMismatch
        );
        assert_eq!(
            any_err(&v2_with_lens(b + tag, big_records)),
            FormatError::LengthMismatch
        );
    }

    #[test]
    fn v2_shares_v1_key_block_checks() {
        let ok = valid_file_v2();
        let set = |i: usize, v: u8| {
            let mut f = ok.clone();
            f[i] = v;
            f
        };
        assert_eq!(any_err(&set(10, 1)), FormatError::BadFlags);
        assert_eq!(any_err(&set(11, 0x80)), FormatError::BadFlags);
        assert_eq!(any_err(&set(12, 2)), FormatError::UnknownKdf(2));
        for i in 13..16 {
            assert_eq!(any_err(&set(i, 1)), FormatError::ReservedNotZero);
        }
        let mut f = ok.clone();
        f[OFF_MEMORY..OFF_MEMORY + 4].copy_from_slice(&65_535u32.to_le_bytes());
        assert_eq!(
            any_err(&f),
            FormatError::KdfPolicy(KdfParamsError::BelowFloor)
        );
        let mut f = ok.clone();
        f[OFF_PARALLELISM..OFF_PARALLELISM + 4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            any_err(&f),
            FormatError::KdfPolicy(KdfParamsError::UnsupportedParallelism)
        );
        assert_eq!(any_err(&set(0, b'X')), FormatError::BadMagic);
    }

    #[test]
    fn version_3_unsupported() {
        for v in [0u8, 3, 4, 255] {
            let mut f = valid_file_v2();
            f[8] = v;
            assert_eq!(any_err(&f), FormatError::UnsupportedVersion(u16::from(v)));
        }
        let mut f = valid_file_v2();
        f[9] = 1;
        assert_eq!(any_err(&f), FormatError::UnsupportedVersion(0x0102));
        assert!(
            FormatError::UnsupportedVersion(3)
                .to_string()
                .contains("newer")
        );
    }

    #[test]
    fn header_parse_is_v1_only() {
        // Header::parse refuses a valid v2 header, whatever FORMAT_VERSION is.
        assert_eq!(
            Header::parse(&valid_file_v2()).expect_err("v2 is not v1"),
            FormatError::UnsupportedVersion(2)
        );
    }

    #[test]
    fn v2_key_block_is_first_132_bytes_and_carries_version_2() {
        let h = valid_header_v2();
        let kb = h.key_block();
        assert_eq!(kb[..], h.encode()[..KEY_BLOCK_LEN]);
        assert_eq!(kb[8..10], 2u16.to_le_bytes());
        // Same fields in a v1 header give the same bytes except the version.
        let v1 = valid_header().encode();
        assert_eq!(v1[..8], kb[..8]);
        assert_eq!(v1[10..KEY_BLOCK_LEN], kb[10..]);
    }

    #[test]
    fn new_errors_have_distinct_messages() {
        assert_ne!(
            FormatError::IndexLength.to_string(),
            FormatError::RecordsLength.to_string()
        );
    }
}
