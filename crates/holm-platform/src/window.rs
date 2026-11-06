//! The macOS window and session, read straight from AppKit (feature `gui-window`).
//!
//! egui-winit reads a window's minimised state on macOS only when the window is
//! created (egui issue 3494: winit's query hops to the main thread and can deadlock),
//! so the vault would never lock on minimise. holm-gui asks AppKit here instead, from
//! the main thread itself, so nothing hops and nothing waits.
//!
//! [`LockEvents`] listens for the moments the vault must lock: the Mac going to
//! sleep, the screens sleeping, the screen locking, and the user session going inactive
//! (fast user switching or logout). Each one sets a shared flag that the app reads once
//! per frame.

#![allow(
    unsafe_code,
    reason = "a pointer cast from the window handle to its NSView, reading AppKit's \
              notification names, and adding and removing notification observers; each \
              block has a SAFETY comment"
)]

use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use block2::RcBlock;
use objc2::MainThreadMarker;
use objc2::rc::Retained;
use objc2::runtime::{NSObjectProtocol, ProtocolObject};
use objc2_app_kit::{
    NSView, NSWorkspace, NSWorkspaceScreensDidSleepNotification,
    NSWorkspaceSessionDidResignActiveNotification, NSWorkspaceWillSleepNotification,
};
use objc2_foundation::{
    NSDistributedNotificationCenter, NSNotification, NSNotificationCenter, NSNotificationName,
    NSOperationQueue, NSString, NSTimeZone,
};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};

/// The distributed notification macOS posts when the screen locks (Ctrl-Cmd-Q, the
/// Lock Screen menu item, or the screen saver asking for the password). AppKit has no
/// constant for it.
const SCREEN_LOCKED: &str = "com.apple.screenIsLocked";

/// The largest UTC offset we report, in seconds: 18 hours. Real zones stay within
/// +-14 hours; anything beyond this is treated as bad data and clamped.
const MAX_UTC_OFFSET_SECS: i32 = 64_800;

/// Seconds east of UTC for the Mac's current time zone, read fresh each call. For display only (the list's "updated" time); stored data stays UTC.
///
/// Clamped to +-18 hours. Falls back to 0 (UTC) if the value does not fit an `i32`.
#[must_use]
pub fn utc_offset_secs() -> i32 {
    let seconds = NSTimeZone::localTimeZone().secondsFromGMT();
    i32::try_from(seconds)
        .unwrap_or(0)
        .clamp(-MAX_UTC_OFFSET_SECS, MAX_UTC_OFFSET_SECS)
}

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

/// One observer: the center it was added to, and the token that removes it.
type Observer = (
    Retained<NSNotificationCenter>,
    Retained<ProtocolObject<dyn NSObjectProtocol>>,
);

/// The OS events that lock the vault: sleep, screens asleep, screen lock, and the user
/// session going inactive (fast user switching or logout).
///
/// Four observers each set one shared [`AtomicBool`]; [`LockEvents::take`] reads and
/// resets it. The observers run on the main queue and capture only that flag, so a
/// notification can never reach the vault itself. Dropping `LockEvents` removes every
/// observer. It holds no secret, and it stays on the main thread (it is not `Send`).
pub struct LockEvents {
    /// Set by any observer, cleared by [`LockEvents::take`].
    flag: Arc<AtomicBool>,
    /// Each observer token with the center it was added to, for removal on drop.
    observers: Vec<Observer>,
}

impl LockEvents {
    /// Starts listening. `None` off the main thread: AppKit's workspace and the main
    /// queue belong to the main thread, so the observers are added only there.
    #[must_use]
    pub fn install() -> Option<LockEvents> {
        let _main_thread = MainThreadMarker::new()?;
        let mut events = LockEvents {
            flag: Arc::new(AtomicBool::new(false)),
            observers: Vec::with_capacity(4),
        };
        let workspace = NSWorkspace::sharedWorkspace().notificationCenter();
        // SAFETY: these are AppKit's exported `NSString` constants. The linker binds them
        // to AppKit's immutable statics before `main`, and reading one only copies a
        // `&'static NSNotificationName`; nothing writes to them.
        let names: [&NSNotificationName; 3] = unsafe {
            [
                NSWorkspaceWillSleepNotification,
                NSWorkspaceScreensDidSleepNotification,
                NSWorkspaceSessionDidResignActiveNotification,
            ]
        };
        for name in names {
            events.observe(&workspace, name);
        }
        let distributed: Retained<NSNotificationCenter> =
            Retained::into_super(NSDistributedNotificationCenter::defaultCenter());
        events.observe(&distributed, &NSString::from_str(SCREEN_LOCKED));
        Some(events)
    }

    /// Adds one observer for `name` on `center` that sets the flag.
    fn observe(&mut self, center: &Retained<NSNotificationCenter>, name: &NSNotificationName) {
        let flag = Arc::clone(&self.flag);
        let block = RcBlock::new(move |_note: NonNull<NSNotification>| {
            flag.store(true, Ordering::SeqCst);
        });
        let queue = NSOperationQueue::mainQueue();
        // SAFETY: `obj` is `None`, so there is no object whose type could be wrong. The
        // queue is the main queue, whose only requirement is that the block may run on
        // the main thread; the block touches nothing but an `Arc<AtomicBool>`, which is
        // `Send` and `Sync`, so it may run on any thread. The center copies (retains) the
        // block, and the token it returns is kept until `Drop` removes it.
        let token = unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(name),
                None,
                Some(&queue),
                &block,
            )
        };
        self.observers.push((Retained::clone(center), token));
    }

    /// Whether an event came since the last call. Reading resets it.
    #[must_use]
    pub fn take(&self) -> bool {
        self.flag.swap(false, Ordering::SeqCst)
    }
}

impl Drop for LockEvents {
    fn drop(&mut self) {
        for (center, token) in self.observers.drain(..) {
            // SAFETY: `token` is the observer object that this same `center` returned
            // from `addObserverForName:object:queue:usingBlock:`, which is exactly the
            // type `removeObserver:` expects. Each token is removed once (drained here).
            unsafe { center.removeObserver(token.as_ref()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use raw_window_handle::{HandleError, HasWindowHandle, WindowHandle};

    use super::{LockEvents, MAX_UTC_OFFSET_SECS, is_minimised, utc_offset_secs};

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

    #[test]
    fn utc_offset_is_within_range() {
        // Range only: some zones have offsets that are not a multiple of 60 seconds.
        let offset = utc_offset_secs();
        assert!(
            (-MAX_UTC_OFFSET_SECS..=MAX_UTC_OFFSET_SECS).contains(&offset),
            "offset {offset} is out of range"
        );
    }

    #[test]
    fn install_off_main_thread_is_none() {
        // A test thread is never the main thread. `LockEvents` is not `Send`, so only
        // the answer comes back.
        let none = std::thread::spawn(|| LockEvents::install().is_none())
            .join()
            .unwrap();
        assert!(none);
    }
}
