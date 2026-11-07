//! Migration tests (v1 to v2). The session-level cases (backup, retry, notes) are in
//! `session::migration_tests`; these cover the conversion function itself.

use super::{backup_tag, v1_to_v2};
use crate::body::VaultData;
use crate::envelope;
use crate::format::{Header, ParsedHeader, parse_any};
use crate::fuzzing::fixture_items;
use holm_crypto::MasterPassword;
use holm_crypto::kdf::{KdfParams, derive_kek};

const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";
const FLOOR: KdfParams = KdfParams::FLOOR;

fn pw(s: &str) -> MasterPassword {
    MasterPassword::new(s.to_owned())
}

fn v1_file(items: usize) -> Vec<u8> {
    let mut d = VaultData::new_default();
    d.items = fixture_items().into_iter().take(items).collect();
    for i in &mut d.items {
        i.fields.clear();
    }
    envelope::create(&pw(PW), &FLOOR, d.encode().unwrap().expose())
        .unwrap()
        .1
}

fn header(file: &[u8]) -> Header {
    let ParsedHeader::V1(h, _) = parse_any(file).unwrap() else {
        panic!("not v1")
    };
    h
}

#[test]
fn tag_is_v1_and_sixteen_hex_digits_of_the_body_nonce() {
    let h = header(&v1_file(0));
    let tag = backup_tag(&h);
    assert_eq!(tag.len(), 3 + 16);
    assert!(tag.starts_with("v1-"));
    assert!(
        tag[3..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    let mut other = h.clone();
    other.body_nonce[0] ^= 0xff;
    assert_ne!(backup_tag(&other), tag);
    assert_eq!(backup_tag(&h), tag, "stable for the same file");
}

#[test]
fn converts_every_item_to_one_record_at_generation_one() {
    let file = v1_file(4);
    let h = header(&file);
    let kek = derive_kek(&pw(PW), &h.salt, &h.kdf).unwrap();
    let (_, plain) = envelope::open_with_kek(&file, &kek).unwrap();
    let data = VaultData::decode(plain.expose()).unwrap();
    let want: Vec<_> = data.items.iter().map(|i| i.id).collect();
    let kek2 = derive_kek(&pw(PW), &h.salt, &h.kdf).unwrap();
    let m = v1_to_v2(kek2, &h, data).unwrap();
    assert_eq!(m.records.len(), 4);
    assert_eq!(m.index.entries.len(), 4);
    for ((e, r), id) in m.index.entries.iter().zip(&m.records).zip(want) {
        assert_eq!(e.id, id);
        assert_eq!(r.generation, 1);
        assert_eq!(e.record.generation, 1);
        assert_eq!(e.record.nonce, r.nonce);
        assert_eq!(usize::try_from(e.record.ct_len).unwrap(), r.ct.len());
    }
    assert!(m.index.migration_backup.is_none());
    assert_eq!(m.tag, backup_tag(&h));
}
