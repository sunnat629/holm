//! Holm platform code: everything that talks to the operating system.
//!
//! For now this is [`fs_store`], the vault file on disk with durable writes, built
//! on the standard library only.

// No `unsafe` yet: everything here uses safe std APIs. When OS code lands (memory
// locking, clipboard, capture exclusion), Phase 5 replaces this crate-wide `forbid`
// with a per-module `#[allow(unsafe_code)]`, each block with a `// SAFETY:` comment.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod fs_store;
