//! Holm's desktop app, built on egui (eframe with the `glow` renderer).
//!
//! The library holds the GUI code so `egui_kittest` can test it headless; the
//! `holm-gui` binary only parses its arguments and opens the window. Phase 3 builds
//! the GUI on macOS only: every GUI module is gated with `#[cfg(target_os = "macos")]`,
//! so on Linux and Windows this library is empty and the workspace still builds and
//! tests there.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(target_os = "macos")]
pub mod fonts;
pub mod secret_input;
#[cfg(target_os = "macos")]
pub mod widgets;
