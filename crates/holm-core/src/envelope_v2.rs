//! The v2 vault envelope: an index sealed on its own, and one sealed record per item.
//!
//! Layout (spec 2.1 to 2.5): a 172-byte header, the index ciphertext, then the records
//! region (record ciphertexts back to back in index order, zero filler up to a 16 KiB
//! multiple).
//!
//! Keys: the same single data key (DEK) seals everything. Every record gets a fresh
//! random 24-byte nonce from [`Nonce::random`]; there are no per-item subkeys.
//!
//! Associated data:
//! - the DEK wrap: header bytes `0..60`, as in v1 (the version field inside is 2, so a
//!   v1 wrap does not open in a v2 header);
//! - the index: the whole 172-byte header, so its lengths and nonce are authenticated;
//! - a record: `"HOLMREC\0"`, the 132-byte key block, the 16-byte item id and the
//!   generation (`u64` LE). The index pins each record's generation and nonce.
//!
//! Records are not opened here when a vault is opened. [`open_v2_with_kek`] checks the
//! header, the index and the framing, then copies each record's ciphertext out unread.
//! [`open_record`] opens one, and any failure there is [`CoreError::DamagedItem`].

use core::fmt;

use holm_crypto::aead::{self, NONCE_LEN, Nonce, TAG_LEN};
use holm_crypto::kdf::{KdfParams, derive_kek};
use holm_crypto::{MasterPassword, SecretKey, random_array};

use crate::body::BodyError;
use crate::envelope::{VaultError, dek_from_unwrapped};
use crate::error::CoreError;
use crate::format::{
    FormatError, HEADER_LEN_V2, HeaderV2, KEY_BLOCK_LEN, MAX_FILE_LEN, ParsedHeader, WRAP_AAD_LEN,
    parse_any,
};
use crate::index::{Index, ItemEntry};
use crate::item::ItemId;
use crate::padding::{
    MAX_RECORD_PADDED, PAD_BLOCK, RECORD_PAD_BLOCK, pad, pad_to, unpad, unpad_from,
};
use crate::record::RecordSecrets;

/// Domain tag at the start of every record's associated data.
const RECORD_TAG: [u8; 8] = *b"HOLMREC\0";
/// Length of a record's associated data: tag, key block, item id, generation.
pub(crate) const RECORD_AAD_LEN: usize = 8 + KEY_BLOCK_LEN + 16 + 8;

/// The keys of an open v2 vault: the data key and the current header.
///
/// Private fields, no `Clone`, `Debug` prints nothing, and the DEK is wiped on drop.
pub(crate) struct KeysV2 {
    dek: SecretKey,
    header: HeaderV2,
}

impl KeysV2 {
    /// The bytes `0..132` of the header, bound into every record's associated data.
    pub(crate) fn key_block(&self) -> [u8; KEY_BLOCK_LEN] {
        self.header.key_block()
    }

    /// The current header.
    pub(crate) fn header(&self) -> &HeaderV2 {
        &self.header
    }

    /// The data key. Tests only.
    #[cfg(test)]
    pub(crate) fn dek(&self) -> &SecretKey {
        &self.dek
    }
}

impl fmt::Debug for KeysV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeysV2([REDACTED])")
    }
}

/// One sealed record as the session keeps it: ciphertext (tag included) and the
/// generation and nonce the index pins. Nothing secret; `Debug` prints sizes only.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SealedRecord {
    pub(crate) generation: u64,
    pub(crate) nonce: [u8; NONCE_LEN],
    pub(crate) ct: Box<[u8]>,
}

impl fmt::Debug for SealedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedRecord")
            .field("generation", &self.generation)
            .field("ct_len", &self.ct.len())
            .finish_non_exhaustive()
    }
}

/// The associated data of one record.
pub(crate) fn record_aad(
    key_block: &[u8; KEY_BLOCK_LEN],
    id: &ItemId,
    generation: u64,
) -> [u8; RECORD_AAD_LEN] {
    let mut out = [0u8; RECORD_AAD_LEN];
    let mut at = 0;
    for part in [
        &RECORD_TAG[..],
        &key_block[..],
        &id.as_bytes()[..],
        &generation.to_le_bytes()[..],
    ] {
        if let Some(dst) = out.get_mut(at..at + part.len()) {
            dst.copy_from_slice(part);
        }
        at += part.len();
    }
    out
}

/// Makes the keys of a new vault: a fresh DEK wrapped under `kek`, with the costs and
/// salt written into the header exactly as given. The index nonce and both lengths are
/// zero until [`assemble`] sets them.
///
/// # Errors
/// [`VaultError::Crypto`] if randomness fails.
pub(crate) fn create_keys_with_kek(
    kek: &SecretKey,
    salt: [u8; 32],
    params: &KdfParams,
) -> Result<KeysV2, VaultError> {
    let dek = SecretKey::generate()?;
    let wrap_nonce = Nonce::random()?;
    let mut header = HeaderV2 {
        kdf: *params,
        salt,
        wrap_nonce: *wrap_nonce.as_bytes(),
        // Neither field below is in the wrap AAD (bytes 0..60).
        wrapped_dek: [0; 48],
        index_nonce: [0; NONCE_LEN],
        index_len: 0,
        records_len: 0,
    };
    let wrap_aad = header.encode();
    let wrapped = aead::seal(kek, wrap_nonce, &wrap_aad[..WRAP_AAD_LEN], dek.expose())?;
    // Unreachable: sealing 32 bytes always gives 32 + 16 = 48.
    header.wrapped_dek =
        <[u8; 48]>::try_from(wrapped.as_slice()).map_err(|_| VaultError::Crypto)?;
    Ok(KeysV2 { dek, header })
}

/// [`create_keys_with_kek`] after the policy check and key derivation: a new salt, then
/// Argon2id under `params`. The policy is checked before any derivation.
///
/// # Errors
/// [`VaultError::KdfPolicy`] if `params` break the policy, [`VaultError::Crypto`] or
/// [`VaultError::OutOfMemory`] if randomness or key derivation fails.
pub(crate) fn create_keys(
    password: &MasterPassword,
    params: &KdfParams,
) -> Result<KeysV2, VaultError> {
    params.validate().map_err(VaultError::KdfPolicy)?;
    let salt = random_array::<32>()?;
    let kek = derive_kek(password, &salt, params)?;
    create_keys_with_kek(&kek, salt, params)
}

/// Rounds the ciphertext total up to the records region length (a `PAD_BLOCK` multiple).
fn region_len(total: u64) -> Option<u64> {
    total.checked_next_multiple_of(PAD_BLOCK as u64)
}

/// Seals one record under the DEK with a fresh nonce.
///
/// The plaintext is encoded, padded to 256-byte blocks and sealed with the record AAD.
/// The caller picks `generation` (one more than the item's last, or 1).
///
/// # Errors
/// [`VaultError::TooLargeToSave`] if the record is over the size cap,
/// [`VaultError::Crypto`] if randomness or the cipher fails.
pub(crate) fn seal_record(
    keys: &KeysV2,
    id: &ItemId,
    generation: u64,
    secrets: &RecordSecrets,
) -> Result<SealedRecord, VaultError> {
    let plaintext = secrets.encode().map_err(|e| match e {
        BodyError::Invalid => VaultError::TooLargeToSave,
        _ => VaultError::Crypto,
    })?;
    let padded = pad_to(plaintext.expose(), RECORD_PAD_BLOCK, MAX_RECORD_PADDED)?;
    drop(plaintext);
    let nonce = Nonce::random()?;
    let nonce_bytes = *nonce.as_bytes();
    let aad = record_aad(&keys.key_block(), id, generation);
    let ct = aead::seal(&keys.dek, nonce, &aad, padded.expose())?;
    Ok(SealedRecord {
        generation,
        nonce: nonce_bytes,
        ct: ct.into_boxed_slice(),
    })
}

/// Opens one record and checks it against its index entry.
///
/// # Errors
/// [`CoreError::DamagedItem`] for any failure: the record does not match the entry's
/// pinned generation, nonce or length, it does not authenticate, its padding is wrong,
/// or its content does not decode or disagrees with the entry.
pub(crate) fn open_record(
    keys: &KeysV2,
    sealed: &SealedRecord,
    entry: &ItemEntry,
) -> Result<RecordSecrets, CoreError> {
    let damaged = || CoreError::DamagedItem(entry.id());
    let pinned = entry.record;
    if sealed.generation != pinned.generation
        || sealed.nonce != pinned.nonce
        || usize::try_from(pinned.ct_len).ok() != Some(sealed.ct.len())
    {
        return Err(damaged());
    }
    let aad = record_aad(&keys.key_block(), &entry.id(), sealed.generation);
    let padded = aead::open(&keys.dek, &sealed.nonce, &aad, &sealed.ct).map_err(|_| damaged())?;
    let plaintext = unpad_from(padded.expose(), RECORD_PAD_BLOCK).map_err(|_| damaged())?;
    drop(padded);
    RecordSecrets::decode(plaintext.expose(), entry).map_err(|_| damaged())
}

/// Builds a whole v2 file: header, sealed index, record ciphertexts in index order, zero
/// filler. `keys` gets the new header (index nonce and lengths) only if the call succeeds.
///
/// The size check comes first, before anything is sealed.
///
/// # Errors
/// [`VaultError::TooLargeToSave`] if the file would pass [`MAX_FILE_LEN`] or the index is
/// not encodable; [`VaultError::Crypto`] if `records` do not match the index entries one
/// for one (a caller bug) or randomness fails.
pub(crate) fn assemble(
    keys: &mut KeysV2,
    index: &Index,
    records: &[&SealedRecord],
) -> Result<Vec<u8>, VaultError> {
    // One record per entry, each exactly as the index pins it.
    if records.len() != index.entries.len() {
        return Err(VaultError::Crypto);
    }
    let mut total: u64 = 0;
    for (entry, record) in index.entries.iter().zip(records) {
        let pinned = entry.record;
        if record.generation != pinned.generation
            || record.nonce != pinned.nonce
            || usize::try_from(pinned.ct_len).ok() != Some(record.ct.len())
        {
            return Err(VaultError::Crypto);
        }
        total = total
            .checked_add(u64::from(pinned.ct_len))
            .ok_or(VaultError::TooLargeToSave)?;
    }
    let records_len = region_len(total).ok_or(VaultError::TooLargeToSave)?;

    let plaintext = index.encode().map_err(|_| VaultError::TooLargeToSave)?;
    let padded = pad(plaintext.expose())?;
    drop(plaintext);
    let index_len = padded
        .len()
        .checked_add(TAG_LEN)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(VaultError::TooLargeToSave)?;
    // Holm never writes a file it would refuse to read.
    let file_len = (HEADER_LEN_V2 as u64)
        .checked_add(index_len)
        .and_then(|n| n.checked_add(records_len))
        .ok_or(VaultError::TooLargeToSave)?;
    if file_len > MAX_FILE_LEN as u64 {
        return Err(VaultError::TooLargeToSave);
    }

    let nonce = Nonce::random()?;
    let mut header = keys.header.clone();
    header.index_nonce = *nonce.as_bytes();
    header.index_len = index_len;
    header.records_len = records_len;
    let encoded = header.encode();
    let index_ct = aead::seal(&keys.dek, nonce, &encoded, padded.expose())?;
    // Unreachable: the AEAD output is always plaintext length plus the tag.
    if u64::try_from(index_ct.len()).ok() != Some(index_len) {
        return Err(VaultError::Crypto);
    }

    let mut file =
        Vec::with_capacity(usize::try_from(file_len).map_err(|_| VaultError::TooLargeToSave)?);
    file.extend_from_slice(&encoded);
    file.extend_from_slice(&index_ct);
    for record in records {
        file.extend_from_slice(&record.ct);
    }
    // The filler: exactly what is needed to reach the region length.
    let end = usize::try_from(file_len).map_err(|_| VaultError::TooLargeToSave)?;
    file.resize(end, 0);
    keys.header = header;
    Ok(file)
}

/// Opens a v2 vault file with `password`: parse, derive the KEK (after the cost policy
/// has been checked on the public bytes), then [`open_v2_with_kek`].
///
/// # Errors
/// As [`open_v2_with_kek`], plus [`VaultError::Crypto`] or [`VaultError::OutOfMemory`]
/// if key derivation fails.
pub(crate) fn open_v2(
    file: &[u8],
    password: &MasterPassword,
) -> Result<(KeysV2, Index, Vec<SealedRecord>), CoreError> {
    let ParsedHeader::V2(header, _, _) = parse_any(file).map_err(VaultError::from)? else {
        return Err(VaultError::Format(FormatError::UnsupportedVersion(1)).into());
    };
    let kek = derive_kek(password, &header.salt, &header.kdf).map_err(VaultError::from)?;
    open_v2_with_kek(file, &kek)
}

/// Everything [`open_v2`] does after key derivation: unwrap the DEK, open and decode the
/// index, check the framing, and copy each record's ciphertext out. No record is opened.
///
/// # Errors
/// [`CoreError::Vault`] with [`VaultError::Format`] or [`VaultError::KdfPolicy`] for a file
/// refused on its public bytes, or for framing that fails after the index opened (a
/// records length that is not the canonical one, filler that is not zero);
/// [`VaultError::WrongPasswordOrCorrupt`] for a wrong password or any change to the
/// header, wrap or index; [`VaultError::BadPadding`] for an authenticated index with
/// malformed padding; [`CoreError::Body`] for an authenticated index that does not decode.
pub(crate) fn open_v2_with_kek(
    file: &[u8],
    kek: &SecretKey,
) -> Result<(KeysV2, Index, Vec<SealedRecord>), CoreError> {
    let parsed = parse_any(file).map_err(VaultError::from)?;
    let ParsedHeader::V2(header, index_ct, region) = parsed else {
        return Err(VaultError::Format(FormatError::UnsupportedVersion(1)).into());
    };
    // The bytes as they are in the file, not a re-encoding. Unreachable errors:
    // `parse_any` succeeded, so the file holds the whole 172-byte header.
    let head = file
        .get(..HEADER_LEN_V2)
        .ok_or(VaultError::Format(FormatError::TooShort))?;
    let wrap_aad = head
        .get(..WRAP_AAD_LEN)
        .ok_or(VaultError::Format(FormatError::TooShort))?;

    let raw = aead::open(kek, &header.wrap_nonce, wrap_aad, &header.wrapped_dek)
        .map_err(VaultError::from)?;
    let dek = dek_from_unwrapped(&raw)?;
    drop(raw);

    let padded = aead::open(&dek, &header.index_nonce, head, index_ct).map_err(VaultError::from)?;
    let plaintext = unpad(padded.expose())?;
    drop(padded);
    let index = Index::decode(plaintext.expose())?;
    drop(plaintext);

    let records = split_region(&index, header.records_len, region)?;
    Ok((KeysV2 { dek, header }, index, records))
}

/// Checks the framing against the open index and copies each record's ciphertext out.
fn split_region(
    index: &Index,
    records_len: u64,
    region: &[u8],
) -> Result<Vec<SealedRecord>, VaultError> {
    let total = index
        .records_total()
        .ok_or(VaultError::Format(FormatError::RecordsLength))?;
    if region_len(total) != Some(records_len) {
        return Err(VaultError::Format(FormatError::RecordsLength));
    }
    let used = usize::try_from(total).map_err(|_| FormatError::RecordsLength)?;
    let (body, filler) = region
        .split_at_checked(used)
        .ok_or(VaultError::Format(FormatError::RecordsLength))?;
    // Every filler byte is checked, without stopping at the first bad one.
    if filler.iter().fold(0u8, |acc, b| acc | b) != 0 {
        return Err(VaultError::Format(FormatError::Filler));
    }

    let mut out = Vec::with_capacity(index.entries.len());
    let mut rest = body;
    for entry in &index.entries {
        let len = entry
            .record
            .ct_len_usize()
            .ok_or(VaultError::Format(FormatError::RecordsLength))?;
        let (ct, tail) = rest
            .split_at_checked(len)
            .ok_or(VaultError::Format(FormatError::RecordsLength))?;
        out.push(SealedRecord {
            generation: entry.record.generation,
            nonce: entry.record.nonce,
            ct: Box::from(ct),
        });
        rest = tail;
    }
    Ok(out)
}

#[cfg(test)]
mod golden;
#[cfg(test)]
mod tamper;
#[cfg(test)]
mod tests;
