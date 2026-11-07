#![no_main]
//! Raw bytes into the index decoder (schema 4). Must never panic or allocate past its
//! caps (the CI run sets `-malloc_limit_mb`). An index it accepts must re-encode, and
//! that encoding must decode and re-encode to the same bytes.

use holm_core::fuzzing::check_decode_index;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    check_decode_index(bytes);
});
