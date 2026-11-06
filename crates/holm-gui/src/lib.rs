//! Holm's desktop app, built on egui (eframe with the `glow` renderer).
//!
//! The library holds the GUI code so `egui_kittest` can test it headless; the
//! `holm-gui` binary only parses its arguments and opens the window. Phase 3 builds
//! the GUI on macOS only: every module that needs egui is gated with
//! `#[cfg(target_os = "macos")]`. On Linux and Windows only the plain-Rust modules
//! (`messages`, `secret_input`) build, so the workspace still builds and tests there.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(all(feature = "dev-unlock", not(debug_assertions)))]
compile_error!("the dev-unlock feature is for debug builds only");

#[cfg(target_os = "macos")]
pub mod app;
#[cfg(target_os = "macos")]
pub mod clipboard;
#[cfg(all(feature = "dev-unlock", debug_assertions))]
/// Debug-only unlock of an existing vault from an environment variable.
pub mod dev_unlock;
#[cfg(target_os = "macos")]
pub mod file_dialog;
#[cfg(target_os = "macos")]
pub mod fonts;
pub mod messages;
#[cfg(target_os = "macos")]
pub mod rows;
#[cfg(target_os = "macos")]
mod screens;
pub mod secret_input;
#[cfg(target_os = "macos")]
pub mod widgets;
#[cfg(target_os = "macos")]
pub mod worker;
