//! Test-only cross-check of Holm's Argon2id against libsodium. Never shipped.
//!
//! The only `unsafe` code lives in the private `ffi` module below. Everything
//! this crate exposes is a safe function.

#![deny(unsafe_code)]

/// Initialises libsodium. Safe to call more than once and from any thread.
///
/// # Panics
/// Panics if libsodium cannot initialise.
pub fn sodium_init() {
    ffi::sodium_init();
}

/// Argon2id version 1.3 through libsodium's `crypto_pwhash`, with parallelism 1,
/// no secret and no associated data. Returns a 32-byte tag.
///
/// `opslimit` is the number of passes and `memlimit_bytes` the memory in bytes.
/// Call [`sodium_init`] first.
///
/// # Panics
/// Panics if libsodium rejects the inputs or runs out of memory.
#[must_use]
pub fn argon2id13(pwd: &[u8], salt: &[u8; 16], opslimit: u64, memlimit_bytes: usize) -> [u8; 32] {
    ffi::argon2id13(pwd, salt, opslimit, memlimit_bytes)
}

// Security decision (spec §12): this test-only crate may call libsodium through
// FFI. All `unsafe` is confined to this module and each block has a SAFETY note.
#[allow(unsafe_code)]
mod ffi {
    #![deny(unsafe_op_in_unsafe_fn)]

    use libsodium_sys as sodium;

    // `argon2id13` takes the salt as `&[u8; 16]`. That is only sound if libsodium
    // reads exactly 16 salt bytes, so pin it at compile time.
    const _: () = assert!(sodium::crypto_pwhash_SALTBYTES == 16);

    pub(super) fn sodium_init() {
        // SAFETY: `sodium_init` takes no arguments and is documented as safe to
        // call more than once and from several threads. It returns 0 on
        // success, 1 if already initialised and -1 on failure.
        let rc = unsafe { sodium::sodium_init() };
        assert!(rc >= 0, "libsodium failed to initialise");
    }

    pub(super) fn argon2id13(
        pwd: &[u8],
        salt: &[u8; 16],
        opslimit: u64,
        memlimit_bytes: usize,
    ) -> [u8; 32] {
        let mut out = [0u8; 32];
        let outlen = u64::try_from(out.len()).expect("32 fits in u64");
        let pwdlen = u64::try_from(pwd.len()).expect("password length fits in u64");
        let alg = i32::try_from(sodium::crypto_pwhash_ALG_ARGON2ID13).expect("small constant");
        // SAFETY:
        // - `out` is a live, writable 32-byte array and `outlen` is exactly 32,
        //   so libsodium writes only inside it.
        // - `pwd` is a live slice; libsodium reads `pwdlen` bytes from it. For
        //   an empty slice the pointer is non-null and nothing is read.
        // - `salt` points to 16 readable bytes, and the const assert above
        //   proves libsodium reads exactly `crypto_pwhash_SALTBYTES` (16).
        // - The buffers do not overlap (`out` is a fresh local), and libsodium
        //   keeps no pointer to any of them after it returns.
        // - Bad sizes or limits make it return -1; it does not read out of bounds.
        let rc = unsafe {
            sodium::crypto_pwhash(
                out.as_mut_ptr(),
                outlen,
                pwd.as_ptr().cast(),
                pwdlen,
                salt.as_ptr(),
                opslimit,
                memlimit_bytes,
                alg,
            )
        };
        assert_eq!(rc, 0, "libsodium crypto_pwhash failed");
        out
    }
}
