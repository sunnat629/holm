#![no_main]
//! Raw bytes into `VaultData::decode`, the bounded postcard decode. Must never
//! panic or allocate past its caps (the CI run sets `-malloc_limit_mb`). A body
//! it accepts must re-encode, and that encoding must be stable.

use holm_core::body::VaultData;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let Ok(data) = VaultData::decode(bytes) else {
        return;
    };
    let encoded = data.encode().expect("a decoded body re-encodes");
    let back = VaultData::decode(encoded.expose()).expect("its encoding decodes");
    assert_eq!(back.item_count(), data.item_count());
    let again = back.encode().expect("re-encodes again");
    assert_eq!(again.expose(), encoded.expose(), "encoding is not stable");
});
