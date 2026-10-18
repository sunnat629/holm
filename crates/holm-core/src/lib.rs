//! Holm core: the vault file format and key hierarchy.
//!
//! [`format`](mod@format) holds the strict v1 header parser and serializer, [`envelope`]
//! creates, opens, re-saves and re-keys a vault, and [`padding`] hides the
//! exact body size. [`text`], [`item`] and [`category`] hold the item model: wiping
//! text types, items and categories. [`rules`] holds the field rules, and [`generator`]
//! makes passwords, passphrases and usernames.
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
//! The same check passes for a type that does implement the trait, so the failures
//! above come from the missing impl and not from a typo:
//!
//! ```
//! fn needs_serialize<T: serde::Serialize>() {}
//! needs_serialize::<holm_core::item::ItemId>();
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod category;
pub mod envelope;
pub mod format;
pub mod generator;
pub mod item;
pub mod padding;
pub mod rules;
pub mod text;
pub(crate) mod wire;
