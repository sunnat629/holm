//! Holm cryptography: secret types, randomness, Argon2id and XChaCha20-Poly1305.
//!
//! Secret types live in [`secret`], errors in [`error`], OS randomness in [`random`]. The primitives arrive in later tasks.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod random;
pub mod secret;

pub use error::{CryptoError, KdfParamsError};
pub use random::{fill_random, random_array};
pub use secret::{MasterPassword, SecretBuf, SecretKey};
