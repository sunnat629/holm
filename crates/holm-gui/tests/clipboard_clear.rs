#![cfg(target_os = "macos")]
//! The GUI clears a copied password after the vault's clipboard time, on lock and on
//! quit, and only when the clipboard still holds Holm's value. Headless, with a fake
//! clipboard and a clock the test moves by hand.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{
    FakeClipboard, PASSWORD, TestClock, harness, make_vault, make_vault_with_clipboard, run_until,
    test_app_with_clipboard,
};
use eframe::App as _;
use eframe::egui::Event;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use holm_core::settings::CLIPBOARD_DEFAULT_SECS;
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::messages;

const WAIT: Duration = Duration::from_secs(30);
const SECRET: &str = "EXAMPLE-zq9-pass";

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

/// An unlocked vault holding one login, with its password copied. Returns the harness,
/// the shared clock and the fake clipboard.
fn copied(dir: &Path) -> (Harness<'static, HolmApp>, TestClock, FakeClipboard) {
    make_vault(dir, PASSWORD);
    copied_in_made_vault(dir)
}

/// [`copied`] on a vault the caller already made.
fn copied_in_made_vault(dir: &Path) -> (Harness<'static, HolmApp>, TestClock, FakeClipboard) {
    let fake = FakeClipboard::default();
    let (app, clock) = test_app_with_clipboard(dir, Box::new(fake.clone()));
    let mut harness = harness(app);
    harness.run();
    type_into(&mut harness, "Master password", PASSWORD);
    harness.key_press(eframe::egui::Key::Enter);
    harness.step();
    run_until(&mut harness, |a| a.screen_kind() == ScreenKind::Vault, WAIT);
    harness.run();

    harness.get_by_label("New login").click();
    harness.run();
    type_into(&mut harness, "Title", "Example Mail");
    type_into(&mut harness, "Password", SECRET);
    harness.get_by_label("Save").click();
    harness.step();
    run_until(&mut harness, |a| a.screen_kind() == ScreenKind::Vault, WAIT);
    harness.run();

    harness.get_by_label("Copy").click();
    harness.run();
    assert_eq!(fake.0.borrow().contents.as_deref(), Some(SECRET));
    (harness, clock, fake)
}

#[test]
fn gui_copy_clears_after_vault_secs() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock, fake) = copied(dir.path());
    let secs = u64::from(CLIPBOARD_DEFAULT_SECS);

    clock.advance(Duration::from_secs(secs - 1));
    harness.step();
    assert_eq!(fake.0.borrow().clears, 0, "not yet");
    assert_eq!(fake.0.borrow().contents.as_deref(), Some(SECRET));

    clock.advance(Duration::from_secs(1));
    harness.step();
    harness.run();
    assert_eq!(fake.0.borrow().clears, 1);
    assert_eq!(fake.0.borrow().contents, None);
    assert!(
        harness
            .query_by_label(messages::CLIPBOARD_CHANGED)
            .is_none()
    );
}

#[test]
fn gui_copy_left_alone_when_changed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock, fake) = copied(dir.path());
    fake.0.borrow_mut().contents = Some("EXAMPLE-from-another-app".to_owned());

    clock.advance(Duration::from_secs(u64::from(CLIPBOARD_DEFAULT_SECS)));
    harness.step();
    harness.run();
    assert_eq!(
        fake.0.borrow().clears,
        0,
        "someone else's copy is not ours to clear"
    );
    assert_eq!(
        fake.0.borrow().contents.as_deref(),
        Some("EXAMPLE-from-another-app")
    );
    let _ = harness.get_by_label(messages::CLIPBOARD_CHANGED);
}

#[test]
fn gui_lock_clears_clipboard_now() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, fake) = copied(dir.path());

    harness.get_by_label("Lock").click();
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert_eq!(fake.0.borrow().clears, 1);
    assert_eq!(fake.0.borrow().contents, None);
}

#[test]
fn gui_quit_clears_clipboard() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, fake) = copied(dir.path());

    harness.state_mut().on_exit(None);
    assert_eq!(fake.0.borrow().clears, 1);
    assert_eq!(fake.0.borrow().contents, None);
}

#[test]
fn gui_copy_uses_the_vaults_clipboard_time() {
    let dir = tempfile::tempdir().unwrap();
    make_vault_with_clipboard(dir.path(), PASSWORD, 10);
    let (mut harness, clock, fake) = copied_in_made_vault(dir.path());
    let _ = harness.get_by_label(&messages::copied_note(10));
    assert!(
        harness
            .query_by_label(&messages::copied_note(CLIPBOARD_DEFAULT_SECS))
            .is_none()
    );

    clock.advance(Duration::from_secs(9));
    harness.step();
    assert_eq!(fake.0.borrow().clears, 0, "not yet at 9 s");
    assert_eq!(fake.0.borrow().contents.as_deref(), Some(SECRET));

    clock.advance(Duration::from_secs(1));
    harness.step();
    harness.run();
    assert_eq!(fake.0.borrow().clears, 1, "cleared at 10 s");
    assert_eq!(fake.0.borrow().contents, None);
}

#[test]
fn gui_failed_clear_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock, fake) = copied(dir.path());
    fake.0.borrow_mut().clear_sticks = true;

    clock.advance(Duration::from_secs(u64::from(CLIPBOARD_DEFAULT_SECS)));
    harness.step();
    harness.run();
    assert_eq!(fake.0.borrow().clears, 1);
    let _ = harness.get_by_label(messages::CLIPBOARD_NOT_CLEARED);
    assert!(
        harness
            .query_by_label(&messages::copied_note(CLIPBOARD_DEFAULT_SECS))
            .is_none()
    );
}

#[test]
fn gui_failed_clear_on_lock_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, fake) = copied(dir.path());
    fake.0.borrow_mut().clear_sticks = true;

    harness.get_by_label("Lock").click();
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert_eq!(fake.0.borrow().clears, 1);
    // The vault view is gone, so the unlock screen carries the line.
    let _ = harness.get_by_label_contains(messages::CLIPBOARD_NOT_CLEARED);
}
