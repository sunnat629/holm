#![no_main]
//! Raw bytes into the version-agnostic header parser. Must never panic. A v1
//! or v2 header it accepts re-encodes to the same leading bytes, and the
//! slices that follow add up to the whole file.

use holm_core::format::{HEADER_LEN, HEADER_LEN_V2, ParsedHeader, parse_any};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match parse_any(data) {
        Ok(ParsedHeader::V1(header, body)) => {
            assert_eq!(&header.encode()[..], &data[..HEADER_LEN]);
            assert_eq!(body, &data[HEADER_LEN..]);
        }
        Ok(ParsedHeader::V2(header, index, records)) => {
            assert_eq!(&header.encode()[..], &data[..HEADER_LEN_V2]);
            assert_eq!(index, &data[HEADER_LEN_V2..HEADER_LEN_V2 + index.len()]);
            assert_eq!(HEADER_LEN_V2 + index.len() + records.len(), data.len());
        }
        Err(_) => {}
    }
});
