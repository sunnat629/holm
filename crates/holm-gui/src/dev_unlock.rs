//! Debug-only unlock from the environment, for developers who are tired of typing.
//!
//! This module exists only when the `dev-unlock` feature is on in a debug build; a
//! release build with the feature stops with a `compile_error!` in `lib.rs`.
//!
//! The variable stays in the process environment for the life of the process (removing
//! it needs `unsafe` in edition 2024, which this crate forbids), so other code in the
//! process and, depending on the OS, other processes of the same user can read it.
//! Never use it with a real vault password.

use holm_crypto::MasterPassword;

/// The environment variable that holds the developer's test password.
pub const ENV_VAR: &str = "HOLM_DEV_PASSWORD";

/// The password from [`ENV_VAR`], or `None` when it is unset, not valid UTF-8 or empty.
/// The `String` is moved into the wiping type, not copied.
#[must_use]
pub fn password_from_env() -> Option<MasterPassword> {
    let value = std::env::var(ENV_VAR).ok()?;
    (!value.is_empty()).then(|| MasterPassword::new(value))
}
