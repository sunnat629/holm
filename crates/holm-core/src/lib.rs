//! Holm core: the vault file format and key hierarchy.
//!
//! [`format`](mod@format) holds the strict v1 header parser and serializer, [`envelope`]
//! creates, opens, re-saves and re-keys a vault, and [`padding`] hides the
//! exact body size. [`text`], [`item`] and [`category`] hold the item model: wiping
//! text types, items and categories, and the one set of field rules.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod category;
pub mod envelope;
pub mod format;
pub mod item;
pub mod padding;
pub mod text;
