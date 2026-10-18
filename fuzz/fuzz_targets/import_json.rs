#![no_main]
//! Raw bytes into `import::parse` as JSON, the hostile-input importer. Must never
//! panic or allocate past its caps (the CI run sets `-malloc_limit_mb`). A file
//! it accepts never yields more rows than `MAX_IMPORT_ROWS`.

use holm_core::import::{ImportFormat, MAX_IMPORT_ROWS, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let Ok(batch) = parse(bytes, ImportFormat::Json) else {
        return;
    };
    assert!(batch.ready() + batch.issues().len() <= MAX_IMPORT_ROWS);
});
