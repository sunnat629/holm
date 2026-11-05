//! Hostile input for the vault body decoder, through the public API only.
//!
//! Every case must return an error, never panic, and no error may show body bytes in
//! its `Display` or `Debug`. The bodies carry the marker `EXAMPLE` in secret places, so
//! a leak shows up in the text checks.
//!
//! The item wire types are private to holm-core, so the schema 2 bytes are written by
//! hand in the `wire.rs` field order: id, title, category, favourite, created, updated,
//! trashed, data, fields; each custom field is position, label, kind tag, value, expiry.
//! `ItemId` is a newtype over `[u8; 16]`, which postcard writes as 16 raw bytes with no
//! length prefix; a zero timestamp, `None` and `false` are each one zero byte. The layout
//! is also pinned by checking that the decoder's own re-encoding gives back exactly the
//! bytes built here.

use holm_core::body::{BODY_SCHEMA_V1, BODY_SCHEMA_VERSION, BodyError, VaultData};
use holm_core::rules::MAX_CUSTOM_FIELDS;

/// Stands in for a secret: it must never appear in an error or in `Debug`.
const MARKER: &str = "EXAMPLE";

/// The item id on the wire: `ItemId([u8; 16])` is 16 raw bytes.
const ITEM_ID: [u8; 16] = [0x11; 16];

/// Postcard variant index of `DataIn::SecureNote` (Login 0, CryptoAddress 1,
/// RecoveryPhrase 2, SecureNote 3).
const DATA_SECURE_NOTE: u8 = 3;

/// Postcard variant index of `CustomValueIn::Secret` (Text 0, Secret 1,
/// MultilineSecret 2, Date 3).
const KIND_SECRET: u8 = 1;

fn default_v2() -> Vec<u8> {
    VaultData::new_default()
        .encode()
        .expect("the default vault encodes")
        .expose()
        .to_vec()
}

/// The default body without its last two bytes (item count 0, next category id 4).
fn default_prefix() -> Vec<u8> {
    let mut b = default_v2();
    let len = b.len();
    assert_eq!(b[len - 2..], [0, 4], "default body ends: no items, next id 4");
    b.truncate(len - 2);
    b
}

/// Appends a postcard string. Test strings stay under 128 bytes, so the length is one
/// varint byte.
fn push_str(out: &mut Vec<u8>, s: &str) {
    let len = u8::try_from(s.len()).expect("short test string");
    assert!(len < 0x80, "one-byte varint length");
    out.push(len);
    out.extend_from_slice(s.as_bytes());
}

/// The test item's bytes (a secure note), without its field list. Identical in
/// schema 1 and schema 2.
fn item_bytes() -> Vec<u8> {
    let mut item = ITEM_ID.to_vec();
    push_str(&mut item, "Title");
    item.push(0); // category: None
    item.push(0); // favourite: false
    item.push(0); // created: 0
    item.push(0); // updated: 0
    item.push(0); // trashed: None
    item.push(DATA_SECURE_NOTE);
    push_str(&mut item, &format!("{MARKER}-note-body"));
    item
}

/// A field count, then `count` secret fields at positions 0, 1, … with distinct labels.
fn fields(count: u8) -> Vec<u8> {
    assert!(count < 0x80, "one-byte varint count");
    let mut out = vec![count];
    for i in 0..count {
        out.push(i); // position (u8, one raw byte)
        push_str(&mut out, &format!("Label {i}"));
        out.push(KIND_SECRET);
        push_str(&mut out, &format!("{MARKER}-field-secret"));
        out.push(0); // expiry: None
    }
    out
}

/// A schema 2 body: default settings and categories, one item with `count` custom
/// fields, then the next category id.
fn body_with_fields(count: u8) -> Vec<u8> {
    let mut b = default_prefix();
    b.push(1); // one item
    b.extend_from_slice(&item_bytes());
    b.extend_from_slice(&fields(count));
    b.push(4); // next category id
    b
}

fn max_fields() -> u8 {
    u8::try_from(MAX_CUSTOM_FIELDS).expect("field cap fits in u8")
}

fn assert_no_marker(err: BodyError) {
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains(MARKER), "error text shows body bytes");
}

#[test]
fn hand_built_body_is_canonical() {
    for n in [0, 1, max_fields()] {
        let body = body_with_fields(n);
        let data = VaultData::decode(&body).expect("hand-built body decodes");
        assert_eq!(data.item_count(), 1);
        assert_eq!(data.encode().expect("re-encodes").expose(), body.as_slice());
    }
}

#[test]
fn empty_and_one_byte_are_too_short() {
    assert_eq!(VaultData::decode(&[]).unwrap_err(), BodyError::TooShort);
    assert_eq!(VaultData::decode(&[1]).unwrap_err(), BodyError::TooShort);
    assert_eq!(VaultData::decode(&[2]).unwrap_err(), BodyError::TooShort);
}

#[test]
fn version_zero_is_unknown() {
    assert_eq!(
        VaultData::decode(&[0, 0]).unwrap_err(),
        BodyError::UnknownSchema(0)
    );
    let mut b = default_v2();
    b[..2].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(
        VaultData::decode(&b).unwrap_err(),
        BodyError::UnknownSchema(0)
    );
}

#[test]
fn newer_versions_are_refused() {
    let next = BODY_SCHEMA_VERSION + 1;
    assert_eq!(next, 3);
    let mut b = default_v2();
    b[..2].copy_from_slice(&next.to_le_bytes());
    assert_eq!(
        VaultData::decode(&b).unwrap_err(),
        BodyError::NewerSchema(next)
    );
    b[..2].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(
        VaultData::decode(&b).unwrap_err(),
        BodyError::NewerSchema(u16::MAX)
    );
    assert_eq!(
        VaultData::decode(&u16::MAX.to_le_bytes()).unwrap_err(),
        BodyError::NewerSchema(u16::MAX)
    );
}

#[test]
fn v1_default_decodes_and_encodes_as_v2() {
    // The v2 default body is the v1 default body with a different version.
    let mut v1 = default_v2();
    v1[..2].copy_from_slice(&BODY_SCHEMA_V1.to_le_bytes());
    let data = VaultData::decode(&v1).expect("the v1 default body decodes");
    assert_eq!(data.item_count(), 0);
    let encoded = data.encode().expect("re-encodes");
    assert_eq!(
        encoded.expose()[..2],
        BODY_SCHEMA_VERSION.to_le_bytes(),
        "a v1 body is written back as v2"
    );
    assert_eq!(encoded.expose()[2..], v1[2..]);
}

#[test]
fn v1_item_migrates_to_v2_with_no_fields() {
    // A v1 item is the v2 item without its field list.
    let mut v1 = default_prefix();
    v1[..2].copy_from_slice(&BODY_SCHEMA_V1.to_le_bytes());
    v1.push(1);
    v1.extend_from_slice(&item_bytes());
    v1.push(4);
    let data = VaultData::decode(&v1).expect("the v1 item decodes");
    assert_eq!(data.item_count(), 1);
    let encoded = data.encode().expect("re-encodes");
    assert_eq!(encoded.expose(), body_with_fields(0).as_slice());
}

#[test]
fn v2_item_relabelled_v1_is_refused() {
    let mut b = body_with_fields(1);
    b[..2].copy_from_slice(&BODY_SCHEMA_V1.to_le_bytes());
    assert!(VaultData::decode(&b).is_err());
}

#[test]
fn every_truncation_fails_without_panic() {
    for body in [default_v2(), body_with_fields(2)] {
        assert!(VaultData::decode(&body).is_ok());
        for n in 0..body.len() {
            let expected = if n < 2 {
                BodyError::TooShort
            } else {
                BodyError::Malformed
            };
            assert_eq!(
                VaultData::decode(&body[..n]).unwrap_err(),
                expected,
                "prefix length {n}"
            );
        }
    }
}

#[test]
fn trailing_bytes_are_malformed() {
    for body in [default_v2(), body_with_fields(1)] {
        for extra in [&[0u8][..], MARKER.as_bytes()] {
            let mut b = body.clone();
            b.extend_from_slice(extra);
            assert_eq!(VaultData::decode(&b).unwrap_err(), BodyError::Malformed);
        }
    }
}

#[test]
fn eleven_custom_fields_are_refused() {
    let at_cap = VaultData::decode(&body_with_fields(max_fields())).expect("cap decodes");
    assert_eq!(at_cap.item_count(), 1);
    let over = max_fields() + 1;
    assert_eq!(over, 11);
    assert_eq!(
        VaultData::decode(&body_with_fields(over)).unwrap_err(),
        BodyError::Malformed
    );
}

#[test]
fn errors_and_debug_show_no_secret() {
    let mut trailing = body_with_fields(1);
    trailing.extend_from_slice(MARKER.as_bytes());
    let mut newer = (BODY_SCHEMA_VERSION + 1).to_le_bytes().to_vec();
    newer.extend_from_slice(MARKER.as_bytes());
    let mut zero = vec![0, 0];
    zero.extend_from_slice(MARKER.as_bytes());
    let mut truncated = body_with_fields(1);
    truncated.truncate(truncated.len() - 3);
    let cases = [
        trailing,
        newer,
        zero,
        truncated,
        body_with_fields(max_fields() + 1),
        MARKER.as_bytes().to_vec(),
        vec![2],
    ];
    for case in cases {
        assert_no_marker(VaultData::decode(&case).unwrap_err());
    }

    let data = VaultData::decode(&body_with_fields(max_fields())).expect("decodes");
    assert!(!format!("{data:?}").contains(MARKER));
}
