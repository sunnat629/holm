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
use crate::fuzzing::fixture_items;
use crate::index::RecordRef;
use crate::record::split;

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
