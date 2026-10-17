//! Holm cryptography: secret types, randomness, Argon2id and XChaCha20-Poly1305.
//!
//! Secret types live in [`secret`], errors in [`error`], OS randomness in [`random`] and
//! Argon2id key derivation in [`kdf`]. XChaCha20-Poly1305 sealing and opening live in [`aead`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod aead;
pub mod error;
pub mod kdf;
pub mod random;
pub mod secret;

pub use error::{CryptoError, KdfParamsError};
pub use random::{fill_random, random_array};
pub use secret::{MasterPassword, SecretBuf, SecretKey};
