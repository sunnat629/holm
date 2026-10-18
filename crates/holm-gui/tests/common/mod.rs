#![cfg(target_os = "macos")]
//! Shared helpers for the `holm-gui` integration tests: a fake clock, an app on a
//! temporary vault path, a kittest harness and a step-until loop.

#![allow(
    dead_code,
    reason = "each test file uses a different subset of these helpers"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use egui_kittest::Harness;
use holm_core::clock::{Clock, SystemClock};
use holm_core::item::Timestamp;
use holm_core::session::Session;
use holm_crypto::MasterPassword;
use holm_crypto::kdf::KdfParams;
use holm_gui::app::{AppConfig, HolmApp, NoClipboard};
use holm_platform::fs_store::FsStore;

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

/// The vault path the test apps use under `dir`: `<dir>/Holm/holm.vault`.
pub fn vault_path(dir: &Path) -> PathBuf {
    dir.join("Holm").join("holm.vault")
}

/// A `HolmApp` on `<dir>/Holm/holm.vault` with `KdfParams::FLOOR`, one shared
/// `TestClock` for the session and the UI, and no clipboard.
pub fn test_app(dir: &Path) -> (HolmApp, TestClock) {
    let clock = TestClock::new();
    let app = HolmApp::new(AppConfig {
        vault_path: vault_path(dir),
        kdf: KdfParams::FLOOR,
        session_clock: Box::new(clock.clone()),
        ui_clock: Box::new(clock.clone()),
        clipboard: Box::new(NoClipboard),
    });
    (app, clock)
}

/// A headless harness that runs `app` the way eframe does: `tick`, then `show`.
pub fn harness(app: HolmApp) -> Harness<'static, HolmApp> {
    Harness::builder()
        .with_context_setup(holm_gui::fonts::install_fonts)
        .with_size([900.0, 600.0])
        .build_ui_state(
            |ui, app: &mut HolmApp| {
                app.tick(ui.ctx());
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
