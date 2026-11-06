//! Holm core: the vault file format and key hierarchy.
//!
//! [`format`](mod@format) holds the strict v1 header parser and serializer, [`envelope`]
//! creates, opens, re-saves and re-keys a vault, and [`padding`] hides the
//! exact body size. [`text`], [`item`] and [`category`] hold the item model: wiping
//! text types, items and categories. [`rules`] holds the field rules, and [`generator`]
//! makes passwords, passphrases and usernames. [`strength`] checks a candidate master
//! password. [`settings`] holds the security settings, and [`body`] encodes and decodes
//! the versioned vault body that the envelope encrypts. [`clock`] gives a monotonic
//! clock and the idle timer, and [`throttle`] slows repeated failed unlocks.
//! [`store`] is the trait the vault file is read and written through, [`session`]
//! creates, unlocks, saves and locks a vault, and [`error`] holds its one error type.
//! [`import`] reads CSV and JSON import files into a vault, all or nothing, and
//! [`export`] writes every item outside the Trash as plaintext CSV or JSON after a password check.
//!
//! The item types have no `Serialize` or `Deserialize`, so outside code cannot turn them
//! into bytes or build them from bytes. These two examples must not compile:
//!
//! ```compile_fail
//! fn needs_serialize<T: serde::Serialize>() {}
//! needs_serialize::<holm_core::item::Item>();
//! ```
//!
//! ```compile_fail
//! fn needs_deserialize<T: serde::de::DeserializeOwned>() {}
//! needs_deserialize::<holm_core::text::GatedSecret>();
//! ```
//!
//! The generator spec types follow the same rule:
//!
//! ```compile_fail
//! fn needs_serialize<T: serde::Serialize>() {}
//! needs_serialize::<holm_core::generator::PasswordSpec>();
//! ```
//!
//! ```compile_fail
//! fn needs_serialize<T: serde::Serialize>() {}
//! needs_serialize::<holm_core::generator::PassphraseSpec>();
//! ```
//!
//! ```compile_fail
//! fn needs_serialize<T: serde::Serialize>() {}
//! needs_serialize::<holm_core::generator::UsernameSpec>();
//! ```
//!
//! So do the settings and the vault body:
//!
//! ```compile_fail
//! fn needs_serialize<T: serde::Serialize>() {}
//! needs_serialize::<holm_core::settings::Settings>();
//! ```
//!
//! ```compile_fail
//! fn needs_deserialize<T: serde::de::DeserializeOwned>() {}
//! needs_deserialize::<holm_core::body::VaultData>();
//! ```
//!
//! The session cannot be turned into bytes either:
//!
//! ```compile_fail
//! fn needs_serialize<T: serde::Serialize>() {}
//! needs_serialize::<holm_core::session::LockOutcome>();
//! ```
//!
//! The same check passes for a type that does implement the trait, so the failures
//! above come from the missing impl and not from a typo:
//!
//! ```
//! fn needs_serialize<T: serde::Serialize>() {}
//! needs_serialize::<holm_core::item::ItemId>();
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod body;
pub mod category;
pub mod clock;
pub mod envelope;
// The `fuzzing` feature seals and opens vaults with a raw KEK and no Argon2. It builds
// only under cargo-fuzz, which sets `--cfg fuzzing`, so no normal or `--all-features`
// build can ship it. scripts/ci-local.sh (fuzzing-guard) proves this still fails.
#[cfg(all(feature = "fuzzing", not(fuzzing)))]
compile_error!("the fuzzing feature is only for cargo-fuzz builds (needs --cfg fuzzing)");
pub mod error;
pub mod export;
pub mod fields;
pub mod format;
// Test-only API for the fuzz targets. Absent from a normal build; see the
// `fuzzing` feature in Cargo.toml.
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
pub mod generator;
pub mod import;
pub mod item;
pub mod padding;
// Own CSV and JSON code for import and export.
pub(crate) mod plain;
pub mod rules;
pub mod search;
pub mod session;
pub mod settings;
pub mod store;
pub mod strength;
pub mod text;
pub mod throttle;
pub(crate) mod wire;
