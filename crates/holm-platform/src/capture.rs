#![forbid(unsafe_code)]
//! Keeping Holm's windows out of screenshots and screen sharing.
//!
//! On macOS every window has a `sharingType`. [`set_capture_protection`] sets it on every
//! window the app owns: `NSWindowSharingNone` (0) when protection is on, so the window
//! server leaves the window out of captures made through the usual APIs, and
//! `NSWindowSharingReadOnly` (1, the system default) when it is off.
//!
//! This is a request to the window server, not a guarantee. Capture through
//! ScreenCaptureKit on newer macOS releases, a phone pointed at the screen, a hardware
//! capture card and malware running as the user can all still see the window.
//!
//! The call needs AppKit, so it works only on macOS with the `gui-window` feature.
//! Everywhere else it returns [`CaptureError::Unsupported`]. It needs no `unsafe`:
//! objc2's AppKit bindings are safe to call when you hold a `MainThreadMarker`, and
//! this function gets one only on the main thread.
//!
//! **Main thread only.** AppKit windows belong to the main thread. Called from any other
//! thread, the function does nothing and returns [`CaptureError::NotMainThread`].

/// Why capture protection could not be set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureError {
    /// This operating system (or this build) has no window capture setting to change.
    Unsupported,
    /// The call was not made on the main thread, where AppKit windows live.
    NotMainThread,
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CaptureError::Unsupported => "hiding the window from captures is not supported here",
            CaptureError::NotMainThread => {
                "hiding the window from captures must run on the main thread"
            }
        })
    }
}

impl std::error::Error for CaptureError {}

/// Whether [`set_capture_protection`] can work in this build: macOS with the
/// `gui-window` feature.
#[must_use]
pub const fn is_supported() -> bool {
    cfg!(all(feature = "gui-window", target_os = "macos"))
}

/// Turns capture protection on or off for every window this app has open now.
///
/// Sets the sharing type only where it differs, so calling this every frame is cheap.
/// Windows the app opens later are not covered until the next call, so call it again
/// when a window may have appeared. Returns how many windows were checked.
///
/// # Errors
/// - [`CaptureError::Unsupported`] off macOS, or without the `gui-window` feature.
/// - [`CaptureError::NotMainThread`] when not called on the main thread.
#[cfg(all(feature = "gui-window", target_os = "macos"))]
pub fn set_capture_protection(enabled: bool) -> Result<usize, CaptureError> {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSWindowSharingType};

    let mtm = MainThreadMarker::new().ok_or(CaptureError::NotMainThread)?;
    let wanted = if enabled {
        NSWindowSharingType::None
    } else {
        NSWindowSharingType::ReadOnly
    };
    let windows = NSApplication::sharedApplication(mtm).windows();
    let count = windows.count();
    for index in 0..count {
        let window = windows.objectAtIndex(index);
        if window.sharingType() != wanted {
            window.setSharingType(wanted);
        }
    }
    Ok(count)
}

/// Not supported in this build: always [`CaptureError::Unsupported`].
///
/// # Errors
/// Always [`CaptureError::Unsupported`].
#[cfg(not(all(feature = "gui-window", target_os = "macos")))]
pub fn set_capture_protection(_enabled: bool) -> Result<usize, CaptureError> {
    Err(CaptureError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(all(feature = "gui-window", target_os = "macos")))]
    #[test]
    fn unsupported_builds_say_so() {
        assert!(!is_supported());
        assert_eq!(set_capture_protection(true), Err(CaptureError::Unsupported));
        assert_eq!(
            set_capture_protection(false),
            Err(CaptureError::Unsupported)
        );
    }

    #[cfg(all(feature = "gui-window", target_os = "macos"))]
    #[test]
    fn off_the_main_thread_it_does_nothing() {
        assert!(is_supported());
        let got = std::thread::spawn(|| set_capture_protection(true))
            .join()
            .unwrap();
        assert_eq!(got, Err(CaptureError::NotMainThread));
    }
}
