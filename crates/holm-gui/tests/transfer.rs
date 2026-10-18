#![cfg(target_os = "macos")]
//! The import and export screens, driven headless through the whole app.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{OTHER_PASSWORD, PASSWORD, TestClock, harness, make_vault, run_until, test_app};
use eframe::egui::{Event, Key, accesskit::Role};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::messages;

const WAIT: Duration = Duration::from_secs(60);
const FIXTURE: &str = "../holm-core/tests/fixtures/import/holm.csv";

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

fn vault_screen(app: &HolmApp) -> bool {
    app.screen_kind() == ScreenKind::Vault
}

fn open(dir: &Path) -> (Harness<'static, HolmApp>, TestClock) {
    make_vault(dir, PASSWORD);
    let (app, clock) = test_app(dir);
    let mut harness = harness(app);
    harness.run();
    type_into(&mut harness, "Master password", PASSWORD);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(&mut harness, vault_screen, WAIT);
    harness.run();
    (harness, clock)
}

fn button(harness: &Harness<'static, HolmApp>, label: &str) -> bool {
    harness
        .query_by_role_and_label(Role::Button, label)
        .is_some()
}

fn click_button(harness: &mut Harness<'static, HolmApp>, label: &str) {
    harness.get_by_role_and_label(Role::Button, label).click();
    harness.run();
}

/// Clicks a button that starts a job and waits for the vault screen again.
fn click_job(harness: &mut Harness<'static, HolmApp>, label: &str) {
    harness.get_by_role_and_label(Role::Button, label).click();
    harness.step();
    run_until(harness, vault_screen, WAIT);
    harness.run();
}

fn disabled(harness: &Harness<'static, HolmApp>, label: &str) -> bool {
    harness
        .get_by_role_and_label(Role::Button, label)
        .accesskit_node()
        .is_disabled()
}

fn has_text(harness: &Harness<'static, HolmApp>, needle: &str) -> bool {
    harness.root().children_recursive().any(|node| {
        let access = node.accesskit_node();
        [access.label(), access.value(), access.description()]
            .iter()
            .flatten()
            .any(|t| t.contains(needle))
    })
}

fn fixture_copy(dir: &Path) -> PathBuf {
    let target = dir.join("source.csv");
    std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE), &target).unwrap();
    target
}

fn start_export(harness: &mut Harness<'static, HolmApp>, path: &Path, password: &str) {
    click_button(harness, "Export...");
    type_into(harness, "File path", path.to_str().unwrap());
    type_into(harness, "Master password to export", password);
    harness
        .get_by_label("I understand this file is not encrypted")
        .click();
    harness.run();
}

#[test]
fn import_preview_then_import_then_warning() {
    let dir = tempfile::tempdir().unwrap();
    let source = fixture_copy(dir.path());
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Import...");
    assert!(disabled(&harness, "Read file"));
    type_into(&mut harness, "File path", source.to_str().unwrap());
    click_job(&mut harness, "Read file");
    assert!(button(&harness, "Import these rows"));
    assert!(has_text(&harness, "Written by: Holm."));
    click_job(&mut harness, "Import these rows");
    assert!(has_text(&harness, "Import finished"));
    assert!(has_text(
        &harness,
        holm_core::import::IMPORT_DELETE_SOURCE_WARNING
    ));
    click_button(&mut harness, "Close");
    // The login from the file is listed.
    assert_eq!(harness.query_all_by_label("Example Portal").count(), 1);
}

#[test]
fn import_oversize_shows_fixed_text() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big.csv");
    std::fs::write(&big, vec![b'a'; 17 * 1024 * 1024]).unwrap();
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", big.to_str().unwrap());
    click_job(&mut harness, "Read file");
    let _ = harness.get_by_label(messages::IMPORT_TOO_BIG);
}

#[test]
fn export_button_needs_password_and_checkbox() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.csv");
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Export...");
    assert!(disabled(&harness, "Export"));
    type_into(&mut harness, "File path", out.to_str().unwrap());
    assert!(disabled(&harness, "Export"));
    type_into(&mut harness, "Master password to export", PASSWORD);
    assert!(disabled(&harness, "Export"));
    harness
        .get_by_label("I understand this file is not encrypted")
        .click();
    harness.run();
    assert!(!disabled(&harness, "Export"));
    assert!(!out.exists());
}

#[test]
fn export_wrong_password_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.csv");
    let (mut harness, _clock) = open(dir.path());
    start_export(&mut harness, &out, OTHER_PASSWORD);
    click_job(&mut harness, "Export");
    let _ = harness.get_by_label(messages::EXPORT_WRONG_PASSWORD);
    assert!(!out.exists());
    assert!(harness.state().secret_buffers_empty());
}

#[test]
fn export_writes_0600_file_that_reimports() {
    let dir = tempfile::tempdir().unwrap();
    let source = fixture_copy(dir.path());
    let out = dir.path().join("out.csv");
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", source.to_str().unwrap());
    click_job(&mut harness, "Read file");
    click_job(&mut harness, "Import these rows");
    click_button(&mut harness, "Close");

    start_export(&mut harness, &out, PASSWORD);
    click_job(&mut harness, "Export");
    assert!(has_text(&harness, "Export finished"));
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("Example Portal"));
    click_button(&mut harness, "Close");

    // The export reads back through the import screen: every row is a duplicate.
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", out.to_str().unwrap());
    click_job(&mut harness, "Read file");
    assert!(has_text(&harness, "Written by: Holm."));
}

#[test]
fn export_existing_path_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.csv");
    std::fs::write(&out, b"keep me").unwrap();
    let (mut harness, _clock) = open(dir.path());
    start_export(&mut harness, &out, PASSWORD);
    click_job(&mut harness, "Export");
    let _ = harness.get_by_label(messages::EXPORT_EXISTS);
    assert_eq!(std::fs::read(&out).unwrap(), b"keep me");
}

#[test]
fn transfer_texts_hold_no_values() {
    let dir = tempfile::tempdir().unwrap();
    let source = fixture_copy(dir.path());
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", source.to_str().unwrap());
    click_job(&mut harness, "Read file");
    for needle in [
        "EXAMPLE-pass-1",
        "example.user",
        "portal.example.com",
        "EXAMPLE-0xaddr01",
        "word00",
        "source.csv",
    ] {
        assert!(!has_text(&harness, needle), "{needle} leaked");
    }
    click_job(&mut harness, "Import these rows");
    for needle in ["EXAMPLE-pass-1", "EXAMPLE-0xaddr01", "word00", "source.csv"] {
        assert!(!has_text(&harness, needle), "{needle} leaked");
    }
}
