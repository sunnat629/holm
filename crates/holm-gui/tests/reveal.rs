#![cfg(target_os = "macos")]
//! The press-and-hold eye on every password input, driven headless through the app.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{PASSWORD, harness, make_vault, run_until, test_app};
use eframe::egui::{Event, Key, accesskit::Role, epaint::Shape};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use holm_gui::app::{HolmApp, LockReason, ScreenKind};
use holm_gui::messages::EYE_LABEL;

const WAIT: Duration = Duration::from_secs(60);

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

fn eyes(harness: &Harness<'static, HolmApp>) -> usize {
    harness
        .query_all_by_role_and_label(Role::Button, EYE_LABEL)
        .count()
}

fn unlocked(dir: &Path) -> Harness<'static, HolmApp> {
    make_vault(dir, PASSWORD);
    let (app, _clock) = test_app(dir);
    let mut harness = harness(app);
    harness.run();
    type_into(&mut harness, "Master password", PASSWORD);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(&mut harness, |a| a.screen_kind() == ScreenKind::Vault, WAIT);
    harness.run();
    harness
}

/// Text shapes and circles on screen: (texts containing "EXAMPLE", circles).
fn painted(harness: &Harness<'static, HolmApp>) -> (usize, usize) {
    let mut texts = 0;
    let mut circles = 0;
    for clipped in &harness.output().shapes {
        match &clipped.shape {
            Shape::Text(t) if t.galley.text().contains("EXAMPLE") => texts += 1,
            Shape::Circle(_) => circles += 1,
            _ => {}
        }
    }
    (texts, circles)
}

#[test]
fn eye_on_create_unlock_and_export() {
    // Create screen: no vault yet, two password fields.
    let dir = tempfile::tempdir().unwrap();
    let (app, _clock) = test_app(dir.path());
    let mut create = harness(app);
    create.run();
    assert_eq!(create.state().screen_kind(), ScreenKind::Create);
    assert_eq!(eyes(&create), 2);

    // Unlock screen: one.
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let (app, _clock) = test_app(dir.path());
    let mut unlock = harness(app);
    unlock.run();
    assert_eq!(unlock.state().screen_kind(), ScreenKind::Unlock);
    assert_eq!(eyes(&unlock), 1);

    // Login form and export form, once unlocked.
    let dir = tempfile::tempdir().unwrap();
    let mut vault = unlocked(dir.path());
    vault.get_by_label("New login").click();
    vault.run();
    assert_eq!(eyes(&vault), 1);
    vault.get_by_label("Cancel").click();
    vault.run();
    vault
        .get_by_role_and_label(Role::Button, "Export...")
        .click();
    vault.run();
    assert_eq!(eyes(&vault), 1);
}

#[test]
fn eye_hides_on_lock() {
    let dir = tempfile::tempdir().unwrap();
    let mut harness = unlocked(dir.path());
    harness
        .get_by_role_and_label(Role::Button, "Export...")
        .click();
    harness.run();
    type_into(&mut harness, "Master password to export", PASSWORD);

    let pos = harness
        .get_by_role_and_label(Role::Button, EYE_LABEL)
        .rect()
        .center();
    harness.hover_at(pos);
    harness.step();
    harness.drag_at(pos);
    harness.step();
    assert_eq!(painted(&harness).0, 1, "password shown while held");

    harness.state_mut().lock(LockReason::Idle);
    harness.step();
    harness.run();
    assert!(harness.state().secret_buffers_empty());
    assert_eq!(painted(&harness).0, 0, "no secret text after lock");
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
}
