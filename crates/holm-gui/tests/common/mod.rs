#![cfg(target_os = "macos")]
//! Shared helpers for the `holm-gui` integration tests: a fake clock, a fake
//! clipboard, an app on a temporary vault path, a kittest harness and a step-until
//! loop.

#![allow(
    dead_code,
    reason = "each test file uses a different subset of these helpers"
)]

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use egui_kittest::Harness;
use holm_core::clock::{Clock, SystemClock};
use holm_core::item::Timestamp;
use holm_core::session::Session;
use holm_crypto::MasterPassword;
use holm_crypto::kdf::KdfParams;
use holm_gui::app::{AppConfig, HolmApp, WindowState};
use holm_gui::clipboard::{Clip, ClipCheck, ClipboardError, NoClipboard, SecretClipboard};
use holm_platform::fs_store::FsStore;
use zeroize::Zeroizing;

/// A strong test master password (fake, contains `EXAMPLE`).
pub const PASSWORD: &str = "correct-Horse-battery-staple-EXAMPLE-9";
/// Another strong password, for a wrong try or a mismatch.
pub const OTHER_PASSWORD: &str = "orange-Kettle-midnight-ladder-EXAMPLE-4";

/// A clock the test moves by hand. Clones share the same time.
#[derive(Clone, Default)]
pub struct TestClock {
    /// Monotonic time in nanoseconds.
    mono_nanos: Arc<AtomicU64>,
    /// Wall-clock seconds since 1970.
    unix_secs: Arc<AtomicI64>,
}

impl TestClock {
    /// A clock at monotonic zero and a fixed wall time.
    pub fn new() -> TestClock {
        let clock = TestClock::default();
        clock.unix_secs.store(1_800_000_000, Ordering::SeqCst);
        clock
    }

    /// Moves both clocks forward by `by`.
    pub fn advance(&self, by: Duration) {
        let nanos = u64::try_from(by.as_nanos()).unwrap();
        self.mono_nanos.fetch_add(nanos, Ordering::SeqCst);
        let secs = i64::try_from(by.as_secs()).unwrap();
        self.unix_secs.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_unix(&self) -> Timestamp {
        Timestamp(self.unix_secs.load(Ordering::SeqCst))
    }

    fn monotonic(&self) -> Duration {
        Duration::from_nanos(self.mono_nanos.load(Ordering::SeqCst))
    }
}

/// What a [`FakeClipboard`] saw and what it serves. Fake data only.
#[derive(Default)]
pub struct FakeClipboardState {
    /// Every text passed to `set`, in order (failed calls included).
    pub sets: Vec<Zeroizing<String>>,
    /// What `get_text` returns.
    pub paste: Option<String>,
    /// How many times `get_text` was called.
    pub gets: usize,
    /// Whether `set` fails.
    pub fail: bool,
    /// What the clipboard holds now: the last good `set`, or what a test put there.
    pub contents: Option<String>,
    /// How many times `clear` was called.
    pub clears: usize,
    /// Whether `clear` does nothing, as a pasteboard that refuses to be emptied.
    pub clear_sticks: bool,
}

/// A clipboard for tests: records `set` calls and serves `paste`. Clones share
/// the same state, so the test keeps one and the app gets another.
#[derive(Clone, Default)]
pub struct FakeClipboard(pub Rc<RefCell<FakeClipboardState>>);

impl FakeClipboard {
    /// A fake whose `get_text` serves `text`.
    pub fn serving(text: &str) -> FakeClipboard {
        let fake = FakeClipboard::default();
        fake.0.borrow_mut().paste = Some(text.to_owned());
        fake
    }
}

impl Clip for FakeClipboard {
    fn set(&mut self, text: &str) -> Result<(), ClipboardError> {
        let mut state = self.0.borrow_mut();
        state.sets.push(Zeroizing::new(text.to_owned()));
        if state.fail {
            Err(ClipboardError::Refused)
        } else {
            state.contents = Some(text.to_owned());
            Ok(())
        }
    }

    fn check(&mut self, text: &str) -> ClipCheck {
        if self.0.borrow().contents.as_deref() == Some(text) {
            ClipCheck::Holds
        } else {
            ClipCheck::Other
        }
    }

    fn clear(&mut self) {
        let mut state = self.0.borrow_mut();
        state.clears += 1;
        if !state.clear_sticks {
            state.contents = None;
        }
    }
}

impl SecretClipboard for FakeClipboard {
    fn get_text(&mut self) -> Option<Zeroizing<String>> {
        let mut state = self.0.borrow_mut();
        state.gets += 1;
        state.paste.clone().map(Zeroizing::new)
    }
}

/// The vault path the test apps use under `dir`: `<dir>/Holm/holm.vault`.
pub fn vault_path(dir: &Path) -> PathBuf {
    dir.join("Holm").join("holm.vault")
}

/// A `HolmApp` on `<dir>/Holm/holm.vault` with `KdfParams::FLOOR`, one shared
/// `TestClock` for the session and the UI, and no clipboard.
pub fn test_app(dir: &Path) -> (HolmApp, TestClock) {
    test_app_with_clipboard(dir, Box::new(NoClipboard))
}

/// [`test_app`] with `clipboard` instead of none.
pub fn test_app_with_clipboard(
    dir: &Path,
    clipboard: Box<dyn SecretClipboard>,
) -> (HolmApp, TestClock) {
    let clock = TestClock::new();
    let app = HolmApp::new(AppConfig {
        vault_path: vault_path(dir),
        kdf: KdfParams::FLOOR,
        session_clock: Box::new(clock.clone()),
        ui_clock: Box::new(clock.clone()),
        clipboard,
    });
    (app, clock)
}

/// A window whose minimised state the test sets by hand, in place of AppKit. Clones
/// share the same state. Starts not minimised.
#[derive(Clone, Default)]
pub struct FakeWindow(Rc<Cell<bool>>);

impl FakeWindow {
    /// Minimises the window (`true`) or brings it back (`false`).
    pub fn set_minimised(&self, minimised: bool) {
        self.0.set(minimised);
    }
}

impl WindowState for FakeWindow {
    fn minimised(&self) -> Option<bool> {
        Some(self.0.get())
    }
}

/// A headless harness that runs `app` the way eframe does: `tick`, then `show`. The
/// window is never minimised.
pub fn harness(app: HolmApp) -> Harness<'static, HolmApp> {
    harness_with_window(app, FakeWindow::default())
}

/// [`harness`] with `window` as the app's window.
pub fn harness_with_window(app: HolmApp, window: FakeWindow) -> Harness<'static, HolmApp> {
    Harness::builder()
        .with_context_setup(holm_gui::fonts::install_fonts)
        .with_size([900.0, 600.0])
        .build_ui_state(
            move |ui, app: &mut HolmApp| {
                app.tick(ui.ctx(), &window);
                app.show(ui);
            },
            app,
        )
}

/// Steps `harness` until `pred` holds, sleeping a little between frames. Panics after
/// `timeout`.
pub fn run_until(
    harness: &mut Harness<'static, HolmApp>,
    pred: impl Fn(&HolmApp) -> bool,
    timeout: Duration,
) {
    let start = Instant::now();
    loop {
        harness.step();
        if pred(harness.state()) {
            return;
        }
        assert!(start.elapsed() < timeout, "condition not reached in time");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Makes a real vault at `<dir>/Holm/holm.vault` with `password`, straight through the
/// core (one Argon2 run), without any app.
pub fn make_vault(dir: &Path, password: &str) {
    let path = vault_path(dir);
    holm_platform::paths::ensure_vault_dir(&path).unwrap();
    let mut session = Session::new(FsStore::new(path), Box::new(SystemClock::new()));
    session
        .create(&MasterPassword::new(password.to_owned()), &KdfParams::FLOOR)
        .unwrap();
}

/// [`make_vault`], then sets the vault's auto-lock time to `auto_lock_secs` and saves.
pub fn make_vault_with_auto_lock(dir: &Path, password: &str, auto_lock_secs: u32) {
    make_vault(dir, password);
    let mut session = Session::new(FsStore::new(vault_path(dir)), Box::new(SystemClock::new()));
    let password = MasterPassword::new(password.to_owned());
    session.unlock(&password).unwrap();
    let settings = holm_core::settings::Settings {
        auto_lock_secs,
        ..session.settings().unwrap().clone()
    };
    // A longer time is a weaker setting, so it needs the password.
    session.update_settings(settings, Some(&password)).unwrap();
}

/// [`make_vault`], then sets the vault's clipboard-clear time to `clipboard_clear_secs`.
pub fn make_vault_with_clipboard(dir: &Path, password: &str, clipboard_clear_secs: u32) {
    make_vault(dir, password);
    let mut session = Session::new(FsStore::new(vault_path(dir)), Box::new(SystemClock::new()));
    let password = MasterPassword::new(password.to_owned());
    session.unlock(&password).unwrap();
    let settings = holm_core::settings::Settings {
        clipboard_clear_secs,
        ..session.settings().unwrap().clone()
    };
    // A shorter time is a stronger setting, so it needs no password.
    session.update_settings(settings, None).unwrap();
}
