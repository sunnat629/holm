//! Hiding Holm's windows from screenshots and screen sharing, behind a trait so the app
//! and its tests never call the OS.
//!
//! The real control is a thin call into `holm_platform::capture`, where the AppKit work
//! lives. Everything runs on the main thread, as the egui frame does.

use holm_platform::capture::{self, CaptureError};

/// Turns window capture protection on or off.
pub trait CaptureControl {
    /// Whether this control can do anything here. When it cannot, the app shows no
    /// toggle and never saves the setting as on.
    fn supported(&self) -> bool;

    /// Makes every window the app has open match `enabled`. Cheap enough to call every
    /// frame while on, which also covers windows opened later.
    ///
    /// # Errors
    /// [`CaptureError`] when the OS setting could not be changed.
    fn apply(&mut self, enabled: bool) -> Result<(), CaptureError>;
}

/// The real control, through AppKit's `NSWindow.sharingType`.
#[derive(Debug, Default)]
pub struct SystemCapture;

impl CaptureControl for SystemCapture {
    fn supported(&self) -> bool {
        capture::is_supported()
    }

    fn apply(&mut self, enabled: bool) -> Result<(), CaptureError> {
        capture::set_capture_protection(enabled).map(|_windows| ())
    }
}

/// A control for platforms or tests with nothing to change: unsupported.
#[derive(Debug, Default)]
pub struct NoCapture;

impl CaptureControl for NoCapture {
    fn supported(&self) -> bool {
        false
    }

    fn apply(&mut self, _enabled: bool) -> Result<(), CaptureError> {
        Err(CaptureError::Unsupported)
    }
}
