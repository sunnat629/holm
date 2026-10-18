//! Error types. No message ever contains key, password or plaintext bytes.

/// Everything that can go wrong in `holm-crypto`.
///
/// Each variant is a fixed message. None carries secret data, so an error can
/// be logged or shown to the user without leaking anything.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The operating system could not provide random bytes.
    #[error("the operating system could not provide random bytes")]
    Rng,
    /// The key-derivation parameters were rejected before any work was done.
    #[error("invalid key-derivation parameters: {0}")]
    KdfParams(KdfParamsError),
    /// The key-derivation function itself failed.
    #[error("key derivation failed")]
    Kdf,
    /// The memory for the key derivation could not be reserved. The work area is
    /// reserved up front, so the process gets this error instead of aborting.
    #[error("not enough memory for key derivation")]
    OutOfMemory,
    /// Decryption failed. Deliberately says nothing about why: a wrong key, a
    /// changed ciphertext and a changed header must look the same.
    #[error("decryption failed")]
    Aead,
    /// A key was not exactly 32 bytes long.
    #[error("key must be exactly 32 bytes")]
    InvalidKeyLength,
}

/// Why a set of Argon2id parameters was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KdfParamsError {
    /// A cost is below the minimum we accept.
    #[error("a cost parameter is below the accepted minimum")]
    BelowFloor,
    /// A cost is above the maximum we accept.
    #[error("a cost parameter is above the accepted maximum")]
    AboveCeiling,
    /// The combined cost (memory times passes) is too large.
    #[error("the combined cost is too large")]
    TooMuchWork,
    /// Only a parallelism of 1 is supported.
    #[error("unsupported parallelism")]
    UnsupportedParallelism,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_error_message_is_opaque() {
        assert_eq!(CryptoError::Aead.to_string(), "decryption failed");
    }
}
