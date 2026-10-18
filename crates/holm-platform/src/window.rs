//! The state of a macOS window, read straight from AppKit (feature `gui-window`).
//!
//! egui-winit reads a window's minimised state on macOS only when the window is
//! created (egui issue 3494: winit's query hops to the main thread and can deadlock),
//! so the vault would never lock on minimise. holm-gui asks AppKit here instead, from
//! the main thread itself, so nothing hops and nothing waits.

#![allow(
    unsafe_code,
    reason = "one pointer cast from the window handle to its NSView; see the SAFETY comment"
)]

use objc2::MainThreadMarker;
use objc2_app_kit::NSView;
use raw_window_handle::{HasWindowHandle, RawWindowHandle};

/// Whether `window` is minimised to the Dock (`NSWindow.isMiniaturized`).
///
/// `None` when this is not the main thread (AppKit views are main-thread only), when
/// no window handle is available or it is not an AppKit one, or when the view is not
/// in a window.
#[must_use]
pub fn is_minimised(window: &impl HasWindowHandle) -> Option<bool> {
    let _main_thread = MainThreadMarker::new()?;
    let handle = window.window_handle().ok()?;
    let RawWindowHandle::AppKit(appkit) = handle.as_raw() else {
        return None;
    };
    // SAFETY: an `AppKitWindowHandle`'s `ns_view` points to a live `NSView` for as long
    // as the `WindowHandle` borrow it came from (`handle`), which outlives `view`. We are
    // on the main thread (checked above), where `NSView` may be used. The reference is
    // shared and only used to call `window`, which retains its result.
    let view: &NSView = unsafe { appkit.ns_view.cast::<NSView>().as_ref() };
    Some(view.window()?.isMiniaturized())
}

#[cfg(test)]
mod tests {
    use raw_window_handle::{HandleError, HasWindowHandle, WindowHandle};

    use super::is_minimised;

    /// A window source that must never be asked for its handle.
    struct MustNotRead;

    impl HasWindowHandle for MustNotRead {
        fn window_handle(&self) -> Result<WindowHandle<'_>, HandleError> {
            panic!("the window handle was read off the main thread")
        }
    }

    /// A window source with no handle.
    struct NoHandle;

    impl HasWindowHandle for NoHandle {
        fn window_handle(&self) -> Result<WindowHandle<'_>, HandleError> {
            Err(HandleError::Unavailable)
        }
    }

    #[test]
    fn off_main_thread_is_unknown_and_reads_nothing() {
        let got = std::thread::spawn(|| is_minimised(&MustNotRead))
            .join()
            .unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn no_handle_is_unknown() {
        // Off the main thread too (a test thread), so this returns before the handle;
        // either way the answer is "unknown", never "not minimised".
        assert_eq!(is_minimised(&NoHandle), None);
    }
}
