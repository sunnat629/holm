//! Item-count limit of the vault body, through the public API only.
//!
//! The decoder refuses a list above `MAX_ITEMS` while reading, and `check_structure`
//! repeats the check. These tests pin the boundary: exactly `MAX_ITEMS` items decode, one
//! more is refused. They were added after a mutation run showed that changing the
//! cross-check from `>` to `>=` was not caught by any test.
//!
//! Bytes are written by hand in the layout described in `body_malformed.rs`.

use holm_core::body::{BodyError, VaultData};
use holm_core::rules::MAX_ITEMS;

/// Postcard variant index of `DataIn::SecureNote`.
const DATA_SECURE_NOTE: u8 = 3;

fn default_prefix() -> Vec<u8> {
    let mut b = VaultData::new_default()
        .encode()
        .expect("the default vault encodes")
        .expose()
        .to_vec();
    let len = b.len();
    assert_eq!(
        b[len - 2..],
        [0, 4],
        "default body ends: no items, next id 4"
    );
    b.truncate(len - 2);
    b
}

/// A postcard varint (LEB128).
fn push_varint(out: &mut Vec<u8>, mut n: usize) {
    while n >= 0x80 {
        out.push(u8::try_from(n & 0x7f).expect("seven bits") | 0x80);
        n >>= 7;
    }
    out.push(u8::try_from(n).expect("under 128"));
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    push_varint(out, s.len());
    out.extend_from_slice(s.as_bytes());
}

/// A schema 3 body with `count` secure notes that differ only in their id.
fn body_with_items(count: usize) -> Vec<u8> {
    let mut b = default_prefix();
    push_varint(&mut b, count);
    for i in 0..count {
        let mut id = [0x11u8; 16];
        id[..8].copy_from_slice(&u64::try_from(i).expect("fits").to_le_bytes());
        b.extend_from_slice(&id);
        push_str(&mut b, "Title");
        b.extend_from_slice(&[0, 0, 0, 0, 0]); // category, favourite, created, updated, trashed
        b.push(DATA_SECURE_NOTE);
        push_str(&mut b, "EXAMPLE note");
        b.push(0); // no custom fields
    }
    b.push(4); // next category id
    b
}

#[test]
fn exactly_max_items_decode() {
    let body = body_with_items(MAX_ITEMS);
    let data = VaultData::decode(&body).expect("a body at the item limit decodes");
    assert_eq!(data.item_count(), MAX_ITEMS);
}

#[test]
fn one_item_over_the_limit_is_refused() {
    let body = body_with_items(MAX_ITEMS + 1);
    assert_eq!(
        VaultData::decode(&body).unwrap_err(),
        BodyError::Malformed,
        "the list cap is enforced while reading"
    );
}
