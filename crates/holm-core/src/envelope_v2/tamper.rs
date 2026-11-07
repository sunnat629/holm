//! Tamper tests for the v2 file (spec 7.3). A fixed KEK, so no Argon2.
//!
//! Every test edits a valid file (or builds a vault from valid parts, then mixes
//! them wrongly) and opens it with `open_v2_all`: unlock, then every record. The rule:
//! no edit ever opens, and an edit to one record names that record.

use super::tests::{Built, build, kek};
use super::*;
use crate::fuzzing::{fixture_items, open_v2_all, seal_v2_items, secret};
use crate::index::RecordRef;
use crate::item::ItemData;
use crate::record::split;

fn damaged(b: &Built, i: usize) -> CoreError {
    CoreError::DamagedItem(b.index.entries[i].id())
}

#[test]
fn tamper_swap_records() {
    let b = build(7);
    let mut f = b.file.clone();
    let (a, c) = (b.record_at(0), b.record_at(1));
    let n = b.record_len(0);
    assert_eq!(n, b.record_len(1));
    let (first, second) = (f[a..a + n].to_vec(), f[c..c + n].to_vec());
    f[a..a + n].copy_from_slice(&second);
    f[c..c + n].copy_from_slice(&first);
    assert_eq!(open_v2_all(&f, &b.kek), Err(damaged(&b, 0)));
}

#[test]
fn tamper_delete_record() {
    let b = build(7);
    // Cut record 0 out and add zeros at the end: the length is still valid, the
    // records are shifted.
    let mut f = b.file.clone();
    let a = b.record_at(0);
    let n = b.record_len(0);
    f.drain(a..a + n);
    f.extend(std::iter::repeat_n(0u8, n));
    assert_eq!(open_v2_all(&f, &b.kek), Err(damaged(&b, 0)));
    // Without the zeros the file is shorter than its header says.
    let mut short = b.file.clone();
    short.drain(a..a + n);
    assert!(matches!(
        open_v2_all(&short, &b.kek),
        Err(CoreError::Vault(VaultError::Format(_)))
    ));
}

#[test]
fn tamper_insert_record() {
    let b = build(7);
    // Put a copy of record 0 at position 1 and drop the same number of filler bytes.
    let mut f = b.file.clone();
    let n = b.record_len(0);
    let copy = f[b.record_at(0)..b.record_at(0) + n].to_vec();
    let at = b.record_at(1);
    f.splice(at..at, copy);
    f.truncate(b.file.len());
    // The shift pushes record 3's tail into the filler, which is checked first.
    assert_eq!(
        open_v2_all(&f, &b.kek).err(),
        Some(CoreError::Vault(VaultError::Format(FormatError::Filler)))
    );
    // Adding bytes changes the file length: refused before any key is used.
    let mut long = b.file.clone();
    long.splice(at..at, vec![0u8; n]);
    assert!(matches!(
        open_v2_all(&long, &b.kek),
        Err(CoreError::Vault(VaultError::Format(_)))
    ));
}

#[test]
fn tamper_reorder_records() {
    let b = build(7);
    // Rotate the first three records.
    let mut f = b.file.clone();
    let n = b.record_len(0);
    let a = b.record_at(0);
    f[a..a + 3 * n].rotate_left(n);
    assert_eq!(open_v2_all(&f, &b.kek), Err(damaged(&b, 0)));
}

#[test]
fn tamper_rollback_one_record() {
    // Item 0 was edited: the index now pins generation 2 and a new nonce. An attacker
    // puts the old generation-1 bytes (same length) back.
    let mut b = build(7);
    let old = b.records[0].clone();
    let (entry, secrets) = split(fixture_items().swap_remove(0));
    let new = seal_record(&b.keys, &entry.id(), 2, &secrets).unwrap();
    assert_eq!(new.ct.len(), old.ct.len());
    b.index.entries[0].record = RecordRef {
        generation: 2,
        nonce: new.nonce,
        ct_len: u32::try_from(new.ct.len()).unwrap(),
    };
    b.records[0] = new;
    let refs: Vec<&SealedRecord> = b.records.iter().collect();
    let file = assemble(&mut b.keys, &b.index, &refs).unwrap();
    assert_eq!(open_v2_all(&file, &b.kek), Ok(4));

    let mut rolled = file.clone();
    let a = b.record_at(0);
    rolled[a..a + old.ct.len()].copy_from_slice(&old.ct);
    assert_eq!(open_v2_all(&rolled, &b.kek), Err(damaged(&b, 0)));
}

#[test]
fn tamper_old_index_new_records() {
    // The vault is saved twice with the same keys: new index, new nonces. The old
    // index with the new records region must not open any record.
    let mut b = build(7);
    let old_file = b.file.clone();
    let (index2, records2) = crate::fuzzing::seal_items(&b.keys, fixture_items()).unwrap();
    let refs: Vec<&SealedRecord> = records2.iter().collect();
    let new_file = assemble(&mut b.keys, &index2, &refs).unwrap();
    assert_eq!(open_v2_all(&new_file, &b.kek), Ok(4));

    let start = b.region_start();
    let mut mixed = old_file.clone();
    assert_eq!(mixed.len(), new_file.len());
    mixed[start..].copy_from_slice(&new_file[start..]);
    assert_eq!(open_v2_all(&mixed, &b.kek), Err(damaged(&b, 0)));

    // The new index with the old records: the other way round.
    let mut other = new_file.clone();
    other[start..].copy_from_slice(&old_file[start..]);
    assert_eq!(open_v2_all(&other, &b.kek).err(), Some(damaged(&b, 0)));
}

#[test]
fn tamper_record_from_other_vault() {
    // Two vaults with the same item ids and generations but different keys.
    let a = build(7);
    let b = build(8);
    let mut f = a.file.clone();
    let at = a.record_at(2);
    let n = a.record_len(2);
    f[at..at + n].copy_from_slice(&b.records[2].ct);
    assert_eq!(open_v2_all(&f, &a.kek), Err(damaged(&a, 2)));
}

#[test]
fn tamper_record_after_password_change() {
    // A password change wraps the DEK under a new KEK, salt and wrap nonce. The key
    // block changes, so a record sealed under the old key block no longer opens, even
    // though the DEK is the same. The records were copied from before the change.
    let b = build(7);
    let new_kek = kek(9);
    let mut moved = create_keys_with_kek(&new_kek, [2; 32], &KdfParams::FLOOR).unwrap();
    // `create_keys_with_kek` made a fresh DEK; put the old one back and re-wrap it.
    moved.dek = SecretKey::from_bytes(&mut b.keys.dek().expose().clone());
    let wrap_nonce = Nonce::random().unwrap();
    moved.header.wrap_nonce = *wrap_nonce.as_bytes();
    let head = moved.header.encode();
    let wrapped = aead::seal(
        &new_kek,
        wrap_nonce,
        &head[..WRAP_AAD_LEN],
        moved.dek.expose(),
    )
    .unwrap();
    moved.header.wrapped_dek = <[u8; 48]>::try_from(wrapped.as_slice()).unwrap();
    assert_ne!(moved.key_block(), b.keys.key_block());

    let refs: Vec<&SealedRecord> = b.records.iter().collect();
    let file = assemble(&mut moved, &b.index, &refs).unwrap();
    // The file is well formed and the DEK unwraps; every record is refused.
    assert_eq!(open_v2_all(&file, &new_kek), Err(damaged(&b, 0)));
}

#[test]
fn tamper_record_from_backup_copy() {
    // A backup copy and the vault each hold a record with the same item id and
    // generation, sealed under the same keys, with different content and so different
    // nonces. The AEAD alone would accept the spliced record; the index pin refuses it.
    let b = build(7);
    let mut alt_item = fixture_items().swap_remove(0);
    alt_item.data = ItemData::Login {
        username: crate::text::Text::new("grace".to_owned()),
        password: secret("other"),
        urls: Vec::new(),
        notes: secret(""),
    };
    alt_item.fields = Vec::new();
    let (entry, alt_secrets) = split(alt_item);
    let alt = seal_record(&b.keys, &entry.id(), 1, &alt_secrets).unwrap();
    assert_eq!(alt.ct.len(), b.records[0].ct.len());
    assert_ne!(alt.nonce, b.records[0].nonce);

    let mut f = b.file.clone();
    let at = b.record_at(0);
    f[at..at + alt.ct.len()].copy_from_slice(&alt.ct);
    assert_eq!(open_v2_all(&f, &b.kek), Err(damaged(&b, 0)));

    // Without the pin the same bytes authenticate under the same key and AAD: the
    // index pin is what stops the splice.
    let aad = record_aad(&b.keys.key_block(), &entry.id(), 1);
    assert!(aead::open(b.keys.dek(), &alt.nonce, &aad, &alt.ct).is_ok());
}

#[test]
fn tamper_truncate_every_length() {
    let b = build(7);
    for n in 0..b.file.len() {
        assert!(
            open_v2_all(&b.file[..n], &b.kek).is_err(),
            "length {n} opened"
        );
    }
}

#[test]
fn tamper_append_byte() {
    let b = build(7);
    for extra in [0u8, 1, 0xff] {
        let mut f = b.file.clone();
        f.push(extra);
        assert!(open_v2_all(&f, &b.kek).is_err(), "appended {extra}");
    }
}

#[test]
fn tamper_flip_every_byte() {
    let b = build(7);
    let start = b.region_start();
    let used_end = b.record_at(4);
    for at in 0..b.file.len() {
        // Every byte up to the end of the used records. In the long zero filler a flip
        // is refused the same way everywhere, and each one costs a full index decode,
        // so it is sampled: the first, the last and every 61st.
        if at > used_end && at != b.file.len() - 1 && at % 61 != 0 {
            continue;
        }
        for bit in [0x01u8, 0x80] {
            let mut f = b.file.clone();
            f[at] ^= bit;
            let got = open_v2_all(&f, &b.kek);
            assert!(got.is_err(), "flip of byte {at} (bit {bit:#x}) opened");
            // A flip in one record's bytes names that record.
            if (start..used_end).contains(&at) {
                let i = (0..4).find(|&i| at < b.record_at(i + 1)).unwrap();
                assert_eq!(got, Err(damaged(&b, i)), "byte {at}");
            }
        }
    }
}

#[test]
fn tamper_filler_nonzero() {
    let b = build(7);
    let used_end = b.record_at(4);
    for at in [
        used_end,
        used_end + 1,
        b.file.len() / 2 + used_end / 2,
        b.file.len() - 1,
    ] {
        let mut f = b.file.clone();
        f[at] = 1;
        assert_eq!(
            open_v2_all(&f, &b.kek).err(),
            Some(CoreError::Vault(VaultError::Format(FormatError::Filler))),
            "byte {at}"
        );
    }
}

#[test]
fn tamper_records_len_not_canonical() {
    // The writer (here, a test with the DEK) seals an index and a header whose records
    // length is a valid multiple of the block, but one block more than the records
    // need. The index authenticates; the framing check still refuses it.
    let mut b = build(7);
    let mut header = b.keys.header().clone();
    header.records_len += 16384;
    // Rebuild by hand: same index plaintext, new header as AAD.
    let plaintext = b.index.encode().unwrap();
    let padded = pad(plaintext.expose()).unwrap();
    let nonce = Nonce::random().unwrap();
    header.index_nonce = *nonce.as_bytes();
    let encoded = header.encode();
    let ct = aead::seal(b.keys.dek(), nonce, &encoded, padded.expose()).unwrap();
    let mut file = encoded.to_vec();
    file.extend_from_slice(&ct);
    file.extend_from_slice(&b.file[b.region_start()..]);
    file.resize(file.len() + 16384, 0);
    assert_eq!(
        open_v2_all(&file, &b.kek).err(),
        Some(CoreError::Vault(VaultError::Format(
            FormatError::RecordsLength
        )))
    );
    let _ = &mut b;
}

#[test]
fn tamper_index_ct_len_out_of_range() {
    let b = build(7);
    for bad in [0u64, 15, 16, 16384, 16385, 16384 + 17] {
        let mut f = b.file.clone();
        f[156..164].copy_from_slice(&bad.to_le_bytes());
        assert!(
            matches!(
                open_v2_all(&f, &b.kek),
                Err(CoreError::Vault(VaultError::Format(_)))
            ),
            "index_len {bad}"
        );
    }
    // Far past the file: refused on the public bytes.
    let mut f = b.file.clone();
    f[156..164].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(
        open_v2_all(&f, &b.kek),
        Err(CoreError::Vault(VaultError::Format(_)))
    ));
}

#[test]
fn tamper_v1_body_as_v2_index() {
    // A v1 body (schema 3 bytes) sealed as a v2 index under the right keys: it is
    // authentic but not a schema-4 index, so it never decodes as one.
    let mut b = build(7);
    let body = crate::body::VaultData::new_default().encode().unwrap();
    let padded = pad(body.expose()).unwrap();
    let nonce = Nonce::random().unwrap();
    let mut header = b.keys.header().clone();
    header.index_nonce = *nonce.as_bytes();
    header.index_len = u64::try_from(padded.len() + TAG_LEN).unwrap();
    header.records_len = 0;
    let encoded = header.encode();
    let ct = aead::seal(b.keys.dek(), nonce, &encoded, padded.expose()).unwrap();
    let mut file = encoded.to_vec();
    file.extend_from_slice(&ct);
    assert!(matches!(
        open_v2_all(&file, &b.kek),
        Err(CoreError::Body(_))
    ));
    let _ = &mut b;
    let _ = seal_v2_items;
}
