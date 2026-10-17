//! Holm cryptography: secret types, randomness, Argon2id and XChaCha20-Poly1305.
//!
//! Secret types live in [`secret`]. The primitives arrive in later tasks.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod secret;

pub use secret::{MasterPassword, SecretBuf, SecretKey};
