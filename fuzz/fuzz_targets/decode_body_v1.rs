#![no_main]
//! Raw bytes as a schema 1 body: the target puts `BODY_SCHEMA_V1` in front of the input
//! and decodes it with `VaultData::decode`. Same contract as `decode_body`: no panic,
//! no allocation past the caps, and an accepted body re-encodes stably. The migration
//! must also hold: the re-encoded body is always schema 2 (`BODY_SCHEMA_VERSION`).

use holm_core::body::{BODY_SCHEMA_V1, BODY_SCHEMA_VERSION, VaultData};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let version = BODY_SCHEMA_V1.to_le_bytes();
    let mut body = Vec::with_capacity(version.len() + bytes.len());
    body.extend_from_slice(&version);
    body.extend_from_slice(bytes);
    let Ok(data) = VaultData::decode(&body) else {
        return;
    };
    let encoded = data.encode().expect("a decoded v1 body re-encodes");
    let newest = BODY_SCHEMA_VERSION.to_le_bytes();
    assert_eq!(
        encoded.expose().get(..newest.len()),
        Some(&newest[..]),
        "a v1 body is not written back as the current schema"
    );
    let back = VaultData::decode(encoded.expose()).expect("its encoding decodes");
    assert_eq!(back.item_count(), data.item_count());
    let again = back.encode().expect("re-encodes again");
    assert_eq!(again.expose(), encoded.expose(), "encoding is not stable");
});
