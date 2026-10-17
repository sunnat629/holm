#![no_main]
//! Raw bytes into the strict header parser. Must never panic.

use holm_core::format::{HEADER_LEN, Header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((header, _body)) = Header::parse(data) {
        assert_eq!(&header.encode()[..], &data[..HEADER_LEN]);
    }
});
