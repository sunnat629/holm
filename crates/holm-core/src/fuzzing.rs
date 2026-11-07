//! Test-only entry points for the fuzz targets. Never part of a shipping build.
//!
//! [`seal_with_kek`] and [`open_with_kek`] skip Argon2: the caller hands in the
//! key-encryption key directly. That turns a full open into microseconds, so
//! the fuzzer can reach the body decode thousands of times a second. The same
//! shortcut in a real build would let anyone holding a key bypass the password
//! policy, which is why the module needs the `fuzzing` feature (or `cfg(test)`).

use holm_crypto::SecretKey;
use holm_crypto::kdf::KdfParams;

use crate::body::VaultData;
use crate::category::CategoryId;
use crate::envelope::{self, VaultError};
use crate::envelope_v2::{self, KeysV2, SealedRecord, seal_record};
use crate::error::CoreError;
use crate::fields::{CalendarDate, FieldValue, RecoveryCode, try_field};
use crate::index::{Index, ItemEntry, RecordRef};
use crate::item::{Item, ItemData, ItemId, Timestamp};
use crate::record::{RecordSecrets, split};
use crate::text::{GatedSecret, SecretText, Text};

/// Seals `body_plaintext` into a complete vault file under `kek`.
///
/// The header carries [`KdfParams::FLOOR`] and an all-zero salt. Neither is
/// used: [`open_with_kek`] takes the KEK directly.
///
/// # Errors
/// [`VaultError::TooLargeToSave`] for a body over the size cap,
/// [`VaultError::Crypto`] if randomness fails.
pub fn seal_with_kek(kek: &SecretKey, body_plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let (_keys, file) = envelope::create_with_kek(kek, [0; 32], &KdfParams::FLOOR, body_plaintext)?;
    Ok(file)
}

/// Opens a vault file with `kek` and decodes its body: everything an unlock
/// does after Argon2.
///
/// # Errors
/// [`CoreError::Vault`] for any file the envelope refuses,
/// [`CoreError::Body`] for an authenticated body that does not decode.
pub fn open_with_kek(file: &[u8], kek: &SecretKey) -> Result<VaultData, CoreError> {
    let (_keys, plaintext) = envelope::open_with_kek(file, kek)?;
    Ok(VaultData::decode(plaintext.expose())?)
}

/// Decodes `bytes` as an index body. An accepted index must re-encode, and that
/// encoding must decode and re-encode to the same bytes. Panics on a violation.
pub fn check_decode_index(bytes: &[u8]) {
    let Ok(index) = Index::decode(bytes) else {
        return;
    };
    let first = index.encode().expect("a decoded index re-encodes");
    let back = Index::decode(first.expose()).expect("its encoding decodes");
    let second = back.encode().expect("re-encodes again");
    assert_eq!(second.expose(), first.expose(), "encoding is not stable");
}

pub(crate) fn fixture_item(n: u8, data: ItemData, fields: Vec<crate::fields::CustomField>) -> Item {
    Item {
        id: ItemId::from_hex(&format!("{n:02x}").repeat(16)).expect("32 hex characters"),
        title: Text::new("Example".to_owned()),
        category: Some(CategoryId(1)),
        favourite: false,
        created: Timestamp(1),
        updated: Timestamp(2),
        trashed: None,
        data,
        fields,
    }
}

pub(crate) fn secret(s: &str) -> SecretText {
    SecretText::new(s.to_owned())
}

/// The fixed items behind the `decode_record` fuzz target and its seeds: one of each
/// kind, the first with every sealed field kind.
pub(crate) fn fixture_items() -> Vec<Item> {
    let field = |label: &str, value: FieldValue| {
        try_field(Text::new(label.to_owned()), value, None).expect("a valid field")
    };
    vec![
        fixture_item(
            1,
            ItemData::Login {
                username: Text::new("ada".to_owned()),
                password: secret("hunter2"),
                urls: vec![Text::new("https://example.com".to_owned())],
                notes: secret("notes"),
            },
            vec![
                field("Site", FieldValue::Text(Text::new("example".to_owned()))),
                field("PIN", FieldValue::Secret(secret("1234"))),
                field(
                    "Since",
                    FieldValue::Date(CalendarDate::from_parts(2026, 1, 2).expect("a date")),
                ),
                field(
                    "Codes",
                    FieldValue::RecoveryCodes(vec![
                        RecoveryCode::new(secret("aaaa"), false),
                        RecoveryCode::new(secret("bbbb"), true),
                    ]),
                ),
                field("Long", FieldValue::MultilineSecret(secret("a\nb"))),
            ],
        ),
        fixture_item(
            2,
            ItemData::CryptoAddress {
                chain: Text::new("Bitcoin".to_owned()),
                address: secret("bc1qexample"),
                memo: secret(""),
                notes: secret(""),
            },
            vec![],
        ),
        fixture_item(
            3,
            ItemData::RecoveryPhrase {
                phrase: GatedSecret::new(secret("one two three")),
                notes: secret("notes"),
            },
            vec![],
        ),
        fixture_item(
            4,
            ItemData::SecureNote {
                body: secret("body"),
            },
            vec![],
        ),
    ]
}

fn fixture_entry(which: u8) -> ItemEntry {
    let mut items = fixture_items();
    let i = usize::from(which) % items.len();
    split(items.swap_remove(i)).0
}

/// Seals `items` as generation 1 under `keys` and returns the index and the records, in
/// the same order.
///
/// # Errors
/// [`VaultError::TooLargeToSave`] for a record over its cap, [`VaultError::Crypto`] if
/// randomness fails.
pub(crate) fn seal_items(
    keys: &KeysV2,
    items: Vec<Item>,
) -> Result<(Index, Vec<SealedRecord>), VaultError> {
    let mut index = Index::new_default();
    let mut records = Vec::with_capacity(items.len());
    for item in items {
        let (mut entry, secrets) = split(item);
        let sealed = seal_record(keys, &entry.id(), 1, &secrets)?;
        entry.record = RecordRef {
            generation: 1,
            nonce: sealed.nonce,
            ct_len: u32::try_from(sealed.ct.len()).map_err(|_| VaultError::TooLargeToSave)?,
        };
        index.entries.push(entry);
        records.push(sealed);
    }
    Ok((index, records))
}

/// A whole v2 file of `items` under `kek`, with the keys and parts it was built from.
///
/// # Errors
/// As [`seal_items`] and `assemble`.
pub(crate) fn seal_v2_items(
    kek: &SecretKey,
    items: Vec<Item>,
) -> Result<(KeysV2, Index, Vec<SealedRecord>, Vec<u8>), VaultError> {
    let mut keys = envelope_v2::create_keys_with_kek(kek, [1; 32], &KdfParams::FLOOR)?;
    let (index, records) = seal_items(&keys, items)?;
    let refs: Vec<&SealedRecord> = records.iter().collect();
    let file = envelope_v2::assemble(&mut keys, &index, &refs)?;
    Ok((keys, index, records, file))
}

/// A v2 vault file of the first `count % 5` fixed items, sealed under `kek` with a fixed
/// salt and the floor costs. For the `open_v2_fixed_key` seeds and edits.
///
/// # Errors
/// As [`seal_v2_items`].
pub fn seal_v2_with_kek(kek: &SecretKey, count: u8) -> Result<Vec<u8>, VaultError> {
    let mut items = fixture_items();
    items.truncate(usize::from(count % 5));
    seal_v2_items(kek, items).map(|(_, _, _, file)| file)
}

/// Opens a v2 file with `kek` (header, unwrap, index, framing) and then opens every
/// record. Returns how many records opened. The first failure is returned.
///
/// # Errors
/// [`CoreError`] for any file the envelope refuses or any record that is damaged.
pub fn open_v2_all(file: &[u8], kek: &SecretKey) -> Result<usize, CoreError> {
    let (keys, index, records) = envelope_v2::open_v2_with_kek(file, kek)?;
    for (entry, sealed) in index.entries.iter().zip(&records) {
        envelope_v2::open_record(&keys, sealed, entry)?;
    }
    Ok(records.len())
}

/// The record plaintext of fixture `which` (0 to 3), for the seed corpus.
///
/// # Panics
/// Never for the fixed fixtures.
#[must_use]
pub fn record_fixture_bytes(which: u8) -> Vec<u8> {
    let mut items = fixture_items();
    let i = usize::from(which) % items.len();
    let (_entry, secrets) = split(items.swap_remove(i));
    secrets
        .encode()
        .expect("a fixture encodes")
        .expose()
        .to_vec()
}

/// Decodes the record plaintext `bytes[1..]` against fixture entry `bytes[0] % 4`. An
/// accepted record must re-encode, and that encoding must decode and re-encode to the
/// same bytes. Panics on a violation.
pub fn check_decode_record(bytes: &[u8]) {
    let Some((&which, plaintext)) = bytes.split_first() else {
        return;
    };
    let entry = fixture_entry(which);
    let Ok(secrets) = RecordSecrets::decode(plaintext, &entry) else {
        return;
    };
    let first = secrets.encode().expect("a decoded record re-encodes");
    let back = RecordSecrets::decode(first.expose(), &entry).expect("its encoding decodes");
    let second = back.encode().expect("re-encodes again");
    assert_eq!(second.expose(), first.expose(), "encoding is not stable");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek(byte: u8) -> SecretKey {
        SecretKey::from_bytes(&mut [byte; 32])
    }

    #[test]
    fn seal_then_open_gives_the_same_body() {
        let body = VaultData::new_default().encode().expect("default encodes");
        let file = seal_with_kek(&kek(7), body.expose()).expect("seals");
        let data = open_with_kek(&file, &kek(7)).expect("opens");
        assert_eq!(data.item_count(), 0);
        assert_eq!(data.encode().expect("re-encodes").expose(), body.expose());
    }

    #[test]
    fn any_flipped_byte_or_other_key_is_refused() {
        let body = VaultData::new_default().encode().expect("default encodes");
        let file = seal_with_kek(&kek(7), body.expose()).expect("seals");
        assert!(matches!(
            open_with_kek(&file, &kek(8)),
            Err(CoreError::Vault(VaultError::WrongPasswordOrCorrupt))
        ));
        for i in [0, 59, 60, 163, 164, file.len() - 1] {
            let mut bad = file.clone();
            bad[i] ^= 0x01;
            assert!(open_with_kek(&bad, &kek(7)).is_err(), "byte {i}");
        }
    }

    #[test]
    fn an_authenticated_body_that_does_not_decode_is_a_body_error() {
        let file = seal_with_kek(&kek(7), b"not postcard").expect("seals");
        assert!(matches!(
            open_with_kek(&file, &kek(7)),
            Err(CoreError::Body(_))
        ));
    }

    #[test]
    fn record_fixtures_pass_the_decode_check() {
        for which in 0..4u8 {
            let mut input = vec![which];
            input.extend_from_slice(&record_fixture_bytes(which));
            check_decode_record(&input);
            // The record decodes against its own entry.
            let entry = fixture_entry(which);
            assert!(RecordSecrets::decode(&record_fixture_bytes(which), &entry).is_ok());
        }
        // A record against another kind's entry is refused, not a panic.
        let mut cross = vec![1u8];
        cross.extend_from_slice(&record_fixture_bytes(0));
        check_decode_record(&cross);
        assert!(RecordSecrets::decode(&record_fixture_bytes(0), &fixture_entry(1)).is_err());
    }

    #[test]
    fn index_check_accepts_default_and_ignores_junk() {
        let default = Index::new_default().encode().expect("encodes");
        check_decode_index(default.expose());
        check_decode_index(&[]);
        check_decode_index(&[4, 0, 1, 2, 3]);
    }

    /// Writes the `decode_index` and `decode_record` fuzz seeds. Run once:
    /// `cargo test -p holm-core --lib write_decode_seeds -- --ignored`
    #[test]
    #[ignore = "writes fuzz/seeds/decode_index and decode_record; run once and commit"]
    fn write_decode_seeds() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds");
        let idx = root.join("decode_index");
        let rec = root.join("decode_record");
        std::fs::create_dir_all(&idx).expect("create seed dir");
        std::fs::create_dir_all(&rec).expect("create seed dir");
        let default = Index::new_default().encode().expect("encodes");
        std::fs::write(idx.join("default_index"), default.expose()).expect("write seed");
        for which in 0..4u8 {
            let mut bytes = vec![which];
            bytes.extend_from_slice(&record_fixture_bytes(which));
            std::fs::write(rec.join(format!("fixture_{which}")), bytes).expect("write seed");
        }
    }

    /// Writes the `open_v2_fixed_key` fuzz seeds (KEK `[7; 32]`). Run once:
    /// `cargo test -p holm-core --lib write_open_v2_seeds -- --ignored`
    #[test]
    #[ignore = "writes fuzz/seeds/open_v2_fixed_key; run once and commit"]
    fn write_open_v2_seeds() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/seeds/open_v2_fixed_key");
        std::fs::create_dir_all(&dir).expect("create seed dir");
        let kek = kek(7);
        for (name, count) in [("raw_empty", 0u8), ("raw_four_items", 4)] {
            let mut bytes = vec![0u8];
            bytes.extend_from_slice(&seal_v2_with_kek(&kek, count).expect("seals"));
            std::fs::write(dir.join(name), bytes).expect("write seed");
        }
        // Mode 1: seal `count` items, then apply up to 4 (u32 LE offset, xor) edits.
        std::fs::write(dir.join("sealed_four_items"), [1u8, 4]).expect("write seed");
        std::fs::write(dir.join("sealed_empty"), [1u8, 0]).expect("write seed");
        std::fs::write(
            dir.join("sealed_edit_record"),
            [1u8, 4, 0x80, 0x41, 0, 0, 1],
        )
        .expect("write seed");
    }
}
