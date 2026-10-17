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

/// XChaCha20-Poly1305 (IETF construction) through libsodium's
/// `crypto_aead_xchacha20poly1305_ietf_encrypt`. Returns ciphertext followed by
/// the 16-byte tag. Call [`sodium_init`] first.
///
/// # Panics
/// Panics if libsodium reports an error.
#[must_use]
pub fn xchacha_encrypt(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], msg: &[u8]) -> Vec<u8> {
    ffi::xchacha_encrypt(key, nonce, aad, msg)
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

    // `xchacha_encrypt` takes fixed-size key and nonce arrays. That is only sound
    // if libsodium reads exactly that many bytes, so pin both at compile time.
    const _: () = assert!(sodium::crypto_aead_xchacha20poly1305_ietf_KEYBYTES == 32);
    const _: () = assert!(sodium::crypto_aead_xchacha20poly1305_ietf_NPUBBYTES == 24);
    const _: () = assert!(sodium::crypto_aead_xchacha20poly1305_ietf_ABYTES == 16);

    pub(super) fn xchacha_encrypt(
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        msg: &[u8],
    ) -> Vec<u8> {
        let mut out = vec![0u8; msg.len() + 16];
        let mut out_len: u64 = 0;
        let msg_len = u64::try_from(msg.len()).expect("message length fits in u64");
        let aad_len = u64::try_from(aad.len()).expect("aad length fits in u64");
        // SAFETY:
        // - `out` is a live, writable buffer of `msg.len() + 16` bytes, which is
        //   the maximum libsodium writes (message plus the 16-byte tag, pinned by
        //   the const assert above).
        // - `out_len` is a live `u64`; libsodium writes the produced length to it.
        // - `msg` and `aad` are live slices read for `msg_len` and `aad_len`
        //   bytes. Empty slices have non-null pointers and nothing is read.
        // - `nonsec` (the unused secret nonce) is null, which the API allows.
        // - `nonce` and `key` point to exactly 24 and 32 readable bytes (const
        //   asserts above).
        // - No buffer overlaps another, and libsodium keeps no pointer after return.
        let rc = unsafe {
            sodium::crypto_aead_xchacha20poly1305_ietf_encrypt(
                out.as_mut_ptr(),
                &raw mut out_len,
                msg.as_ptr(),
                msg_len,
                aad.as_ptr(),
                aad_len,
                std::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };
        assert_eq!(rc, 0, "libsodium xchacha encrypt failed");
        assert_eq!(
            out_len,
            u64::try_from(out.len()).expect("fits"),
            "unexpected output length"
        );
        out
    }
}
