//! Unit tests for the v2 envelope: round trips, framing, limits and the exact AAD bytes.
//! Every test uses a fixed KEK, so none runs Argon2.

use std::collections::HashSet;

use super::*;
use crate::fuzzing::{fixture_item, fixture_items, open_v2_all, seal_v2_items, secret};
use crate::index::RecordRef;
use crate::item::ItemData;
use crate::record::split;

pub(super) fn kek(byte: u8) -> SecretKey {
    SecretKey::from_bytes(&mut [byte; 32])
}

/// A sealed vault of the four fixture items with the parts it was built from.
pub(super) struct Built {
    pub(super) kek: SecretKey,
    pub(super) keys: KeysV2,
    pub(super) index: Index,
    pub(super) records: Vec<SealedRecord>,
    pub(super) file: Vec<u8>,
}

pub(super) fn build(kek_byte: u8) -> Built {
    let kek = kek(kek_byte);
    let (keys, index, records, file) = seal_v2_items(&kek, fixture_items()).unwrap();
    Built {
        kek,
        keys,
        index,
        records,
        file,
    }
}

impl Built {
    /// Where the records region starts in the file.
    pub(super) fn region_start(&self) -> usize {
        HEADER_LEN_V2 + usize::try_from(self.keys.header().index_len).unwrap()
    }

    /// Where record `i` starts in the file.
    pub(super) fn record_at(&self, i: usize) -> usize {
        self.region_start()
            + self.index.entries[..i]
                .iter()
                .map(|e| e.record.ct_len_usize().unwrap())
                .sum::<usize>()
    }

    pub(super) fn record_len(&self, i: usize) -> usize {
        self.index.entries[i].record.ct_len_usize().unwrap()
    }
}

/// The encoded record bytes, to compare two sets of secrets without `PartialEq`.
fn record_bytes(secrets: &RecordSecrets) -> Vec<u8> {
    secrets.encode().unwrap().expose().to_vec()
}

#[test]
fn v2_roundtrip_every_record_opens_and_matches() {
    let b = build(7);
    let (keys, index, records) = open_v2_with_kek(&b.file, &b.kek).unwrap();
    assert_eq!(keys.header(), b.keys.header());
    assert_eq!(records, b.records);
    assert_eq!(index.entries.len(), 4);
    let originals: Vec<Vec<u8>> = fixture_items()
        .into_iter()
        .map(|i| record_bytes(&split(i).1))
        .collect();
    for ((entry, sealed), want) in index.entries.iter().zip(&records).zip(&originals) {
        let secrets = open_record(&keys, sealed, entry).unwrap();
        assert_eq!(&record_bytes(&secrets), want);
    }
    assert_eq!(open_v2_all(&b.file, &b.kek), Ok(4));
}

#[test]
fn v2_layout_matches_the_header() {
    let b = build(7);
    let h = b.keys.header();
    assert_eq!(
        h.index_len % 16384,
        16,
        "index is padded blocks plus the tag"
    );
    // Four 272-byte records round up to one block.
    assert_eq!(h.records_len, 16384);
    assert_eq!(
        b.file.len() as u64,
        HEADER_LEN_V2 as u64 + h.index_len + h.records_len
    );
    assert_eq!(&b.file[..HEADER_LEN_V2], &h.encode()[..]);
    // After the four ciphertexts the rest of the region is zero.
    assert!(b.file[b.record_at(4)..].iter().all(|&x| x == 0));
    for e in &b.index.entries {
        assert_eq!(e.record.ct_len, 272);
        assert_eq!(e.record.generation, 1);
    }
}

#[test]
fn v2_empty_vault_has_no_records_region() {
    let kek = kek(3);
    let (keys, index, records, file) = seal_v2_items(&kek, Vec::new()).unwrap();
    assert!(records.is_empty() && index.entries.is_empty());
    assert_eq!(keys.header().records_len, 0);
    assert_eq!(
        file.len() as u64,
        HEADER_LEN_V2 as u64 + keys.header().index_len
    );
    assert_eq!(open_v2_all(&file, &kek), Ok(0));
}

#[test]
fn v2_wrong_kek_is_wrong_password_or_corrupt() {
    let b = build(7);
    let err = open_v2_with_kek(&b.file, &kek(8)).err().unwrap();
    assert_eq!(err, CoreError::Vault(VaultError::WrongPasswordOrCorrupt));
}

#[test]
fn v1_file_is_not_a_v2_file() {
    let (_keys, v1) =
        crate::envelope::create_with_kek(&kek(7), [0; 32], &KdfParams::FLOOR, b"x").unwrap();
    let err = open_v2_with_kek(&v1, &kek(7)).err().unwrap();
    assert!(matches!(
        err,
        CoreError::Vault(VaultError::Format(FormatError::UnsupportedVersion(1)))
    ));
}

#[test]
fn assemble_rejects_records_that_do_not_match_the_index() {
    let mut b = build(7);
    let before = b.keys.header().clone();
    // One record short.
    let short: Vec<&SealedRecord> = b.records.iter().take(3).collect();
    assert_eq!(
        assemble(&mut b.keys, &b.index, &short).err(),
        Some(VaultError::Crypto)
    );
    // A record whose nonce is not the pinned one.
    let mut wrong = b.records.clone();
    wrong[2].nonce[0] ^= 1;
    let refs: Vec<&SealedRecord> = wrong.iter().collect();
    assert_eq!(
        assemble(&mut b.keys, &b.index, &refs).err(),
        Some(VaultError::Crypto)
    );
    assert_eq!(
        b.keys.header(),
        &before,
        "a failed assemble leaves the header alone"
    );
}

#[test]
fn assemble_gives_the_index_a_fresh_nonce_each_time() {
    let mut b = build(7);
    let refs: Vec<&SealedRecord> = b.records.iter().collect();
    let first = b.keys.header().index_nonce;
    let again = assemble(&mut b.keys, &b.index, &refs).unwrap();
    assert_ne!(b.keys.header().index_nonce, first);
    assert_eq!(open_v2_all(&again, &b.kek), Ok(4));
}

#[test]
fn record_aad_golden() {
    let mut key_block = [0u8; KEY_BLOCK_LEN];
    for (i, b) in key_block.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    let id = fixture_item(0x11, ItemData::SecureNote { body: secret("x") }, vec![]).id;
    let aad = record_aad(&key_block, &id, 0x0102_0304_0506_0708);
    let mut want = Vec::new();
    want.extend_from_slice(b"HOLMREC\0");
    want.extend_from_slice(&key_block);
    want.extend_from_slice(&[0x11; 16]);
    want.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(aad.len(), 164);
    assert_eq!(aad.as_slice(), want.as_slice());
}

#[test]
fn records_never_share_a_nonce() {
    let b = build(7);
    let (entry, secrets) = split(fixture_items().swap_remove(0));
    let mut seen = HashSet::new();
    for _ in 0..2000 {
        let sealed = seal_record(&b.keys, &entry.id(), 1, &secrets).unwrap();
        assert!(seen.insert(sealed.nonce), "a nonce repeated");
    }
    // The vault's own records and its index nonce are distinct from those too.
    for r in &b.records {
        assert!(seen.insert(r.nonce));
    }
    assert!(seen.insert(b.keys.header().index_nonce));
}

#[test]
fn seal_record_is_a_whole_number_of_blocks_and_bound_to_the_id_and_generation() {
    let b = build(7);
    let (entry, secrets) = split(fixture_items().swap_remove(0));
    let sealed = seal_record(&b.keys, &entry.id(), 5, &secrets).unwrap();
    assert_eq!((sealed.ct.len() - TAG_LEN) % RECORD_PAD_BLOCK, 0);
    let mut pinned = entry;
    pinned.record = RecordRef {
        generation: 5,
        nonce: sealed.nonce,
        ct_len: u32::try_from(sealed.ct.len()).unwrap(),
    };
    assert!(open_record(&b.keys, &sealed, &pinned).is_ok());
    // The same bytes under another generation or another id do not authenticate, even
    // when the pin is changed to match.
    let mut as_gen6 = sealed.clone();
    as_gen6.generation = 6;
    let mut gen6 = split(fixture_items().swap_remove(0)).0;
    gen6.record = RecordRef {
        generation: 6,
        ..pinned.record
    };
    assert_eq!(
        open_record(&b.keys, &as_gen6, &gen6).err(),
        Some(CoreError::DamagedItem(gen6.id()))
    );
    let mut other = split(fixture_items().swap_remove(1)).0;
    other.record = pinned.record;
    assert_eq!(
        open_record(&b.keys, &sealed, &other).err(),
        Some(CoreError::DamagedItem(other.id()))
    );
}

#[test]
fn v2_file_never_over_cap() {
    // 256 records of the largest size are 67 112 960 bytes: over the 64 MiB cap even
    // before the header and the index. 255 fit.
    let kek = kek(9);
    let mut keys = create_keys_with_kek(&kek, [1; 32], &KdfParams::FLOOR).unwrap();
    let mut index = Index::new_default();
    let mut records = Vec::new();
    for n in 0..=255u8 {
        let (mut entry, _) = split(fixture_item(
            n,
            ItemData::SecureNote { body: secret("x") },
            vec![],
        ));
        let nonce = [n; NONCE_LEN];
        entry.record = RecordRef {
            generation: 1,
            nonce,
            ct_len: 262_160,
        };
        index.entries.push(entry);
        records.push(SealedRecord {
            generation: 1,
            nonce,
            ct: vec![0u8; 262_160].into_boxed_slice(),
        });
    }
    let before = keys.header().clone();
    let all: Vec<&SealedRecord> = records.iter().collect();
    assert_eq!(
        assemble(&mut keys, &index, &all).err(),
        Some(VaultError::TooLargeToSave)
    );
    assert_eq!(keys.header(), &before);

    index.entries.pop();
    let some: Vec<&SealedRecord> = records.iter().take(255).collect();
    let file = assemble(&mut keys, &index, &some).unwrap();
    assert!(file.len() <= MAX_FILE_LEN);
    // The reader accepts the framing of what the writer produced (the records are
    // zero bytes, so only the record opens fail, not the file).
    let (_, back, got) = open_v2_with_kek(&file, &kek).unwrap();
    assert_eq!(back.entries.len(), 255);
    assert_eq!(got.len(), 255);
}
