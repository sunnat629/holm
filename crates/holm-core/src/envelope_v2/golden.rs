//! The committed v2 golden vault, `tests/vectors/golden-v2.vault`.
//!
//! A real v2 file every later version of Holm must still open. It holds the default
//! settings and categories, a login (password, notes, a recovery-code field and more)
//! and a secure note, locked with `"caf\u{e9} golden v2"` at [`KdfParams::FLOOR`].
//!
//! The file is deterministic: salt, data key and nonces are fixed fills, so
//! [`build_golden`] rebuilds it byte for byte. Fixed nonces and a fixed key are for
//! this test vector only. [`build_golden`] is an independent writer: it lays the file
//! out and calls `chacha20poly1305` directly, with its own AAD bytes, and does not use
//! Holm's `assemble` or `seal_record`, so writer and reader check each other. To
//! regenerate after a deliberate, reviewed format change:
//!
//! ```text
//! cargo test -p holm-core --lib write_golden_v2 -- --ignored
//! ```

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInOut, KeyInit};

use super::*;
use crate::category::CategoryId;
use crate::fields::FieldValue;
use crate::fuzzing::fixture_items;
use crate::index::{EntryPublic, FieldEntry, FieldEntryKind, ItemEntry, RecordRef};
use crate::item::{ItemData, ItemId, Timestamp};
use crate::record::{RecordSecrets, join, split};
use crate::text::Text;

const GOLDEN: &[u8] = include_bytes!("../../tests/vectors/golden-v2.vault");
const PASSWORD: &str = "caf\u{e9} golden v2";
const SALT: [u8; 32] = [0x11; 32];
const DEK: [u8; 32] = [0x22; 32];
const WRAP_NONCE: [u8; 24] = [0x33; 24];
const INDEX_NONCE: [u8; 24] = [0x44; 24];
const RECORD_NONCES: [[u8; 24]; 2] = [[0x55; 24], [0x56; 24]];

fn seal_fixed(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut buf = plaintext.to_vec();
    cipher
        .encrypt_in_place(nonce.into(), aad, &mut buf)
        .expect("sealing a small buffer cannot fail");
    buf
}

/// The two items in the vault: the fixture login (with its custom fields) and the note.
fn items() -> Vec<crate::item::Item> {
    let mut all = fixture_items();
    let note = all.pop().unwrap();
    all.truncate(1);
    all.push(note);
    all
}

fn build_golden() -> Vec<u8> {
    let params = KdfParams::FLOOR;
    let pw = MasterPassword::new(PASSWORD.to_owned());
    let kek = derive_kek(&pw, &SALT, &params).unwrap();

    let mut header = HeaderV2 {
        kdf: params,
        salt: SALT,
        wrap_nonce: WRAP_NONCE,
        wrapped_dek: [0; 48],
        index_nonce: [0; 24],
        index_len: 0,
        records_len: 0,
    };
    let wrap_aad = header.encode();
    let wrapped = seal_fixed(kek.expose(), &WRAP_NONCE, &wrap_aad[..60], &DEK);
    header.wrapped_dek = wrapped.try_into().unwrap();
    // Bytes 0..132 of the header, the key block every record binds.
    let key_block = header.encode()[..132].to_vec();

    let mut index = Index::new_default();
    let mut cts = Vec::new();
    for (item, nonce) in items().into_iter().zip(RECORD_NONCES) {
        let (mut entry, secrets) = split(item);
        let id = *entry.id().as_bytes();
        let padded = pad_to(secrets.encode().unwrap().expose(), 256, 262_144).unwrap();
        // The associated data, written out byte by byte.
        let mut aad = Vec::new();
        aad.extend_from_slice(b"HOLMREC\0");
        aad.extend_from_slice(&key_block);
        aad.extend_from_slice(&id);
        aad.extend_from_slice(&1u64.to_le_bytes());
        let ct = seal_fixed(&DEK, &nonce, &aad, padded.expose());
        entry.record = RecordRef {
            generation: 1,
            nonce,
            ct_len: u32::try_from(ct.len()).unwrap(),
        };
        index.entries.push(entry);
        cts.push(ct);
    }

    let padded_index = pad(index.encode().unwrap().expose()).unwrap();
    header.index_nonce = INDEX_NONCE;
    header.index_len = u64::try_from(padded_index.len() + 16).unwrap();
    let total: usize = cts.iter().map(Vec::len).sum();
    header.records_len = u64::try_from(total.next_multiple_of(16384)).unwrap();
    let encoded = header.encode();
    let index_ct = seal_fixed(&DEK, &INDEX_NONCE, &encoded, padded_index.expose());

    let mut file = encoded.to_vec();
    file.extend_from_slice(&index_ct);
    for ct in &cts {
        file.extend_from_slice(ct);
    }
    file.resize(
        HEADER_LEN_V2 + index_ct.len() + usize::try_from(header.records_len).unwrap(),
        0,
    );
    file
}

#[test]
fn golden_v2_rebuilds() {
    assert_eq!(
        build_golden().as_slice(),
        GOLDEN,
        "the independent writer and the vector disagree"
    );
}

#[test]
fn golden_v2_opens() {
    let pw = MasterPassword::new("cafe\u{301} golden v2".to_owned());
    let (keys, index, records) = open_v2(GOLDEN, &pw).unwrap();
    assert_eq!(keys.dek().expose(), &DEK);
    let h = keys.header();
    assert_eq!(h.kdf, KdfParams::FLOOR);
    assert_eq!(h.salt, SALT);
    assert_eq!(h.index_nonce, INDEX_NONCE);
    assert_eq!(
        GOLDEN.len() as u64,
        HEADER_LEN_V2 as u64 + h.index_len + h.records_len
    );
    assert_eq!(index.entries.len(), 2);
    assert_eq!(index.categories.len(), 3);
    let want: Vec<Vec<u8>> = items()
        .into_iter()
        .map(|i| split(i).1.encode().unwrap().expose().to_vec())
        .collect();
    for (i, ((entry, sealed), want)) in index.entries.iter().zip(&records).zip(&want).enumerate() {
        assert_eq!(sealed.nonce, RECORD_NONCES[i]);
        assert_eq!(sealed.generation, 1);
        let got = open_record(&keys, sealed, entry).unwrap();
        assert_eq!(&got.encode().unwrap().expose().to_vec(), want);
    }
    assert_eq!(entry_title(&index, 0), "Example");
    assert_eq!(entry_title(&index, 1), "Example");
    // Every field of both items, against literals written out here, not rebuilt from
    // the fixtures the writer used.
    let open = |i: usize| {
        let secrets = open_record(&keys, &records[i], &index.entries[i]).unwrap();
        join(&index.entries[i], secrets).unwrap()
    };
    let login = open(0);
    assert_eq!(login.id.to_string(), "01".repeat(16));
    assert!(login.category.is_some_and(|c| c == CategoryId(1)));
    assert!(!login.favourite);
    assert_eq!(login.created, Timestamp(1));
    assert_eq!(login.updated, Timestamp(2));
    assert!(login.trashed.is_none());
    let ItemData::Login {
        username,
        password,
        urls,
        notes,
    } = &login.data
    else {
        panic!("item 0 is a login");
    };
    assert_eq!(username.as_str(), "ada");
    assert_eq!(password.expose(), "hunter2");
    let urls: Vec<&str> = urls.iter().map(Text::as_str).collect();
    assert_eq!(urls, ["https://example.com"]);
    assert_eq!(notes.expose(), "notes");
    assert_eq!(login.fields.len(), 5);
    let f = &login.fields;
    assert_eq!(f[0].label(), "Site");
    assert!(matches!(f[0].value(), FieldValue::Text(t) if t.as_str() == "example"));
    assert_eq!(f[1].label(), "PIN");
    assert!(matches!(f[1].value(), FieldValue::Secret(v) if v.expose() == "1234"));
    assert_eq!(f[2].label(), "Since");
    assert!(matches!(f[2].value(), FieldValue::Date(d) if d.parts() == (2026, 1, 2)));
    assert_eq!(f[3].label(), "Codes");
    let FieldValue::RecoveryCodes(codes) = f[3].value() else {
        panic!("field 3 is a list of codes");
    };
    let codes: Vec<(&str, bool)> = codes
        .iter()
        .map(|c| (c.code().expose(), c.used()))
        .collect();
    assert_eq!(codes, [("aaaa", false), ("bbbb", true)]);
    assert_eq!(f[4].label(), "Long");
    assert!(matches!(f[4].value(), FieldValue::MultilineSecret(v) if v.expose() == "a\nb"));
    assert!(f.iter().all(|x| x.expiry().is_none()));

    let note = open(1);
    assert_eq!(note.id.to_string(), "04".repeat(16));
    assert!(matches!(&note.data, ItemData::SecureNote { body } if body.expose() == "body"));
    assert!(note.fields.is_empty());
    // A wrong password does not open it.
    let bad = MasterPassword::new("cafe golden v2".to_owned());
    assert_eq!(
        open_v2(GOLDEN, &bad).err(),
        Some(CoreError::Vault(VaultError::WrongPasswordOrCorrupt))
    );
}

fn entry_title(index: &Index, i: usize) -> &str {
    index.entries[i].title()
}

#[test]
#[ignore = "writes tests/vectors/golden-v2.vault; run after a deliberate format change"]
fn write_golden_v2() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/golden-v2.vault");
    std::fs::write(path, build_golden()).unwrap();
}

/// One index entry, written byte by byte (postcard: varints, zigzag for the signed
/// timestamps, raw arrays, enum variants by index). The Login variant is 0.
#[rustfmt::skip]
const ENTRY_GOLDEN: [u8; 87] = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // id: sixteen 0x01 bytes
    0,                                    // public: Login
    3, b'a', b'd', b'a',                  // username "ada"
    1, 4, b'a', b'.', b'i', b'o',         // one URL "a.io"
    1, 0,                                 // has_password, no notes
    4, b'M', b'a', b'i', b'l',            // title "Mail"
    1, 1,                                 // category: Some(1)
    1,                                    // favourite
    20, 40,                               // created 10, updated 20 (zigzag)
    0,                                    // not trashed
    2,                                    // two custom fields
    0, 3, b'P', b'I', b'N', 1, 0,         // position 0, "PIN", Secret, no expiry
    1, 5, b'C', b'o', b'd', b'e', b's',   // position 1, "Codes"
    4, 2, 0, 1, 0,                        // RecoveryCodes: used [false, true], no expiry
    1,                                    // record: generation 1
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, // nonce
    0x90, 0x02,                           // ct_len 272 (varint)
];

/// The record of [`ENTRY_GOLDEN`]'s item, written byte by byte.
#[rustfmt::skip]
const RECORD_GOLDEN: [u8; 25] = [
    1, 0,                                 // record schema 1, little-endian
    0,                                    // Login
    3, b'p', b'w', b'1',                  // password "pw1"
    0,                                    // notes ""
    2,                                    // two sealed custom values
    0, 0, 4, b'1', b'2', b'3', b'4',      // position 0: Secret "1234"
    1, 2, 2, 2, b'a', b'a', 2, b'b', b'b', // position 1: RecoveryCodes (2) "aa", "bb"
];

fn golden_entry() -> ItemEntry {
    ItemEntry {
        id: ItemId::from_hex(&"01".repeat(16)).unwrap(),
        title: Text::new("Mail".to_owned()),
        category: Some(CategoryId(1)),
        favourite: true,
        created: Timestamp(10),
        updated: Timestamp(20),
        trashed: None,
        public: EntryPublic::Login {
            username: Text::new("ada".to_owned()),
            urls: vec![Text::new("a.io".to_owned())],
            has_password: true,
            has_notes: false,
        },
        fields: vec![
            FieldEntry {
                position: 0,
                label: Text::new("PIN".to_owned()),
                kind: FieldEntryKind::Secret,
                expiry: None,
            },
            FieldEntry {
                position: 1,
                label: Text::new("Codes".to_owned()),
                kind: FieldEntryKind::RecoveryCodes {
                    used: vec![false, true],
                },
                expiry: None,
            },
        ],
        record: RecordRef {
            generation: 1,
            nonce: [9; 24],
            ct_len: 272,
        },
    }
}

#[test]
fn index_entry_golden() {
    // The entry sits between the entry count and the two trailing fields of the
    // default index (next category id 4, no backup note).
    let mut index = Index::new_default();
    index.entries.push(golden_entry());
    let bytes = index.encode().unwrap().expose().to_vec();
    let default = Index::new_default().encode().unwrap().expose().to_vec();
    let head = &default[..default.len() - 3];
    let mut want = head.to_vec();
    want.push(1); // one entry
    want.extend_from_slice(&ENTRY_GOLDEN);
    want.extend_from_slice(&[4, 0]);
    assert_eq!(bytes, want);
    // And the bytes decode to the same entry.
    let back = Index::decode(&want).unwrap();
    assert_eq!(back.entries.len(), 1);
    let e = &back.entries[0];
    assert_eq!(e.title(), "Mail");
    assert_eq!(e.record.generation, 1);
    assert_eq!(e.record.nonce, [9; 24]);
    assert_eq!(e.record.ct_len, 272);
    assert_eq!(e.fields.len(), 2);
}

#[test]
fn record_golden() {
    let entry = golden_entry();
    let secrets = RecordSecrets::decode(&RECORD_GOLDEN, &entry).unwrap();
    assert_eq!(secrets.encode().unwrap().expose(), &RECORD_GOLDEN[..]);
    let item = join(&entry, secrets).unwrap();
    let ItemData::Login {
        username,
        password,
        notes,
        ..
    } = &item.data
    else {
        panic!("a login");
    };
    assert_eq!(username.as_str(), "ada");
    assert_eq!(password.expose(), "pw1");
    assert_eq!(notes.expose(), "");
    assert!(matches!(item.fields[0].value(), FieldValue::Secret(v) if v.expose() == "1234"));
    let FieldValue::RecoveryCodes(codes) = item.fields[1].value() else {
        panic!("codes");
    };
    let codes: Vec<(&str, bool)> = codes
        .iter()
        .map(|c| (c.code().expose(), c.used()))
        .collect();
    assert_eq!(codes, [("aa", false), ("bb", true)]);
}
