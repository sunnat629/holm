#![cfg(target_os = "macos")]
//! The "hide window from screenshots and screen sharing" setting, driven through the
//! whole app with a fake capture control (the real one needs AppKit's main thread).

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use common::{PASSWORD, harness, make_vault, test_app, test_app_with_capture, vault_path};
use egui_kittest::kittest::Queryable;
use holm_gui::capture::CaptureControl;
use holm_gui::messages::HIDE_FROM_CAPTURE_LABEL;
use holm_platform::capture::CaptureError;

/// Records every `apply` call; can be told to fail.
#[derive(Clone, Default)]
struct FakeCapture {
    calls: Rc<RefCell<Vec<bool>>>,
    fail: bool,
}

impl CaptureControl for FakeCapture {
    fn supported(&self) -> bool {
        true
    }

    fn apply(&mut self, enabled: bool) -> Result<(), CaptureError> {
        self.calls.borrow_mut().push(enabled);
        if self.fail {
            Err(CaptureError::NotMainThread)
        } else {
            Ok(())
        }
    }
}

#[test]
fn default_is_off_and_nothing_is_applied() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let fake = FakeCapture::default();
    let (app, _clock) = test_app_with_capture(dir.path(), Box::new(fake.clone()));
    assert!(!app.hide_from_capture());
    let mut harness = harness(app);
    harness.run();
    harness.get_by_label(HIDE_FROM_CAPTURE_LABEL);
    assert!(!harness.state().hide_from_capture());
    assert!(fake.calls.borrow().is_empty());
}

#[test]
fn toggling_applies_at_once_and_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let fake = FakeCapture::default();
    let (app, _clock) = test_app_with_capture(dir.path(), Box::new(fake.clone()));
    let mut harness = harness(app);
    harness.run();
    harness.get_by_label(HIDE_FROM_CAPTURE_LABEL).click();
    harness.run();
    assert!(harness.state().hide_from_capture());
    assert_eq!(fake.calls.borrow().first(), Some(&true));
    assert!(holm_platform::prefs::load(&vault_path(dir.path())).hide_from_capture);
    drop(harness);

    // A new start: applied from the saved setting before the first frame.
    let again = FakeCapture::default();
    let (app, _clock) = test_app_with_capture(dir.path(), Box::new(again.clone()));
    assert!(app.hide_from_capture());
    assert_eq!(again.calls.borrow().as_slice(), &[true]);
    let mut harness = harness(app);
    harness.run();
    // Re-applied each frame while on, for windows opened later.
    assert!(again.calls.borrow().len() > 1);

    // Off again: applied at once with false, and saved.
    harness.get_by_label(HIDE_FROM_CAPTURE_LABEL).click();
    harness.run();
    assert!(!harness.state().hide_from_capture());
    assert_eq!(again.calls.borrow().last(), Some(&false));
    assert!(!holm_platform::prefs::load(&vault_path(dir.path())).hide_from_capture);
}

#[test]
fn a_failed_apply_says_so() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let fake = FakeCapture {
        fail: true,
        ..FakeCapture::default()
    };
    let (app, _clock) = test_app_with_capture(dir.path(), Box::new(fake));
    let mut harness = harness(app);
    harness.run();
    harness.get_by_label(HIDE_FROM_CAPTURE_LABEL).click();
    harness.run();
    harness.get_by_label(holm_gui::messages::HIDE_FROM_CAPTURE_FAILED);
}

#[test]
fn an_unsupported_platform_shows_no_toggle() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    // Even a saved "on" is ignored where nothing can be hidden.
    holm_platform::prefs::save(
        &vault_path(dir.path()),
        holm_platform::prefs::Prefs {
            hide_from_capture: true,
        },
    )
    .unwrap();
    let (app, _clock) = test_app(dir.path());
    assert!(!app.hide_from_capture());
    let mut harness = harness(app);
    harness.run();
    assert!(harness.query_by_label(HIDE_FROM_CAPTURE_LABEL).is_none());
}
