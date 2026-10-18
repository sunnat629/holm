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
pub mod format;
pub mod generator;
pub mod item;
pub mod padding;
pub mod rules;
pub mod settings;
pub mod strength;
pub mod throttle;
pub mod text;
pub(crate) mod wire;
