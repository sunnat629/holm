#![no_main]
//! Record plaintext into the record decoder. The first input byte picks one of four
//! fixed index entries (login, crypto address, recovery phrase, secure note); the rest
//! is decoded against it. Must never panic or allocate past its caps. A record it
//! accepts must re-encode, and that encoding must be stable.

use holm_core::fuzzing::check_decode_record;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    check_decode_record(bytes);
});
