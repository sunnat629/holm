//! Moving an unlocked version 1 vault to format v2, in memory.
//!
//! Nothing here touches the store. [`v1_to_v2`] takes the decoded v1 body and the KEK that
//! opened it, and gives the v2 keys, index and sealed records the session keeps. The
//! session writes them with its first save, through its one write gate, after a backup
//! copy of the v1 file is safe on disk (spec 4).
//!
//! The data key is new, and so are the wrap nonce and the wrap itself, so a v1 wrap does
//! not open in a v2 header. Every record is opened again right after it is sealed and
//! compared with the original in constant time. Any failure is [`CoreError::MigrationFailed`]
//! and the v1 body is dropped (and wiped) on the way out.

use holm_crypto::SecretKey;
use subtle::ConstantTimeEq;

use crate::body::VaultData;
use crate::envelope_v2::{
    KeysV2, SealedRecord, create_keys_with_kek, open_record, seal_record, wrap_opens_to,
};
use crate::error::CoreError;
use crate::format::Header;
use crate::index::{Index, RecordRef};
use crate::record::split;

/// The first generation of every migrated record.
const FIRST_GENERATION: u64 = 1;

/// What a migration gives the session.
pub(crate) struct Migrated {
    pub(crate) keys: KeysV2,
    pub(crate) index: Index,
    /// One sealed record per index entry, in index order.
    pub(crate) records: Vec<SealedRecord>,
    /// The backup tag: `v1-` and the first eight bytes of the v1 body nonce in hex.
    pub(crate) tag: String,
}

/// The backup tag for a v1 file: stable for the same file, different for another save.
pub(crate) fn backup_tag(v1: &Header) -> String {
    let mut tag = String::from("v1-");
    for byte in v1.body_nonce.iter().take(8) {
        tag.push(hex_digit(byte >> 4));
        tag.push(hex_digit(byte & 0x0f));
    }
    tag
}

/// Any error becomes the one opaque migration error.
fn fail<E>(_: E) -> CoreError {
    CoreError::MigrationFailed
}

fn hex_digit(n: u8) -> char {
    char::from(
        b"0123456789abcdef"
            .get(usize::from(n))
            .copied()
            .unwrap_or(b'0'),
    )
}

/// Builds the v2 state from the opened v1 vault.
///
/// `kek` is the key that opened the v1 file; it is used once, to wrap the new data key
/// under the v2 associated data, and dropped before any record is sealed.
///
/// # Errors
/// [`CoreError::MigrationFailed`] for any failure: key or record sealing, a wrap that does
/// not open again, a record that does not open back to the same bytes, or an item the
/// index cannot hold.
pub(crate) fn v1_to_v2(
    kek: SecretKey,
    v1: &Header,
    data: VaultData,
) -> Result<Migrated, CoreError> {
    let keys = create_keys_with_kek(&kek, v1.salt, &v1.kdf).map_err(fail)?;
    if !wrap_opens_to(&keys, &kek) {
        return Err(CoreError::MigrationFailed);
    }
    drop(kek);

    let VaultData {
        settings,
        categories,
        items,
        next_category_id,
    } = data;
    let mut entries = Vec::with_capacity(items.len());
    let mut records = Vec::with_capacity(items.len());
    for item in items {
        let (mut entry, secrets) = split(item);
        let sealed = seal_record(&keys, &entry.id(), FIRST_GENERATION, &secrets).map_err(fail)?;
        let ct_len = u32::try_from(sealed.ct.len()).map_err(|_| CoreError::MigrationFailed)?;
        entry.record = RecordRef {
            generation: sealed.generation,
            nonce: sealed.nonce,
            ct_len,
        };
        // Open it again and compare byte for byte before the original is dropped.
        let back = open_record(&keys, &sealed, &entry).map_err(|_| CoreError::MigrationFailed)?;
        let (before, after) = (
            secrets.encode().map_err(fail)?,
            back.encode().map_err(fail)?,
        );
        if !bool::from(before.expose().ct_eq(after.expose())) {
            return Err(CoreError::MigrationFailed);
        }
        entries.push(entry);
        records.push(sealed);
    }
    let index = Index {
        settings,
        categories,
        entries,
        next_category_id,
        migration_backup: None,
    };
    Ok(Migrated {
        keys,
        index,
        records,
        tag: backup_tag(v1),
    })
}

#[cfg(test)]
mod tests;
