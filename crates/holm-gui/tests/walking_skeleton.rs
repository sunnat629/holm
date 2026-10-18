#![cfg(target_os = "macos")]
//! The Phase 3 walking skeleton, end to end and headless: create a vault, add a login,
//! copy its password, lock, open the vault again in a new app, and see the item. Then
//! check what the flow left on disk.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use common::{
    FakeClipboard, OTHER_PASSWORD, PASSWORD, harness, run_until, test_app_with_clipboard,
    vault_path,
};
use eframe::egui::{Event, Key};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::messages;

const WAIT: Duration = Duration::from_secs(30);
const ROW_TITLE: &str = "Example Mail";
const USERNAME: &str = "ada@example.com";
const URL: &str = "https://mail.example.com";
const URL_HOST: &str = "mail.example.com";
const SECRET: &str = "EXAMPLE-zq9-pass";

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

fn kind_is(kind: ScreenKind) -> impl Fn(&HolmApp) -> bool {
    move |app| app.screen_kind() == kind
}

fn not_working(app: &HolmApp) -> bool {
    app.screen_kind() != ScreenKind::Working
}

/// Types `password` on the unlock screen, presses Enter and waits for the result.
fn try_unlock(harness: &mut Harness<'static, HolmApp>, password: &str) {
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    type_into(harness, "Master password", password);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(harness, not_working, WAIT);
    harness.run();
}

/// The whole Phase 3 flow on `<dir>/Holm/holm.vault`. Every app is dropped before it
/// returns, so the instance lock is released, as when the window closes.
fn run_flow(dir: &Path) {
    let fake = FakeClipboard::default();

    // Create.
    let (app, _clock) = test_app_with_clipboard(dir, Box::new(fake.clone()));
    let mut harness = harness(app);
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Create);
    type_into(&mut harness, "Master password", PASSWORD);
    type_into(&mut harness, "Confirm master password", PASSWORD);
    harness
        .get_by_label("I understand Holm can't recover my vault")
        .click();
    harness.run();
    harness.get_by_label("Create vault").click();
    harness.step();
    run_until(&mut harness, kind_is(ScreenKind::Vault), WAIT);
    harness.run();
    assert!(harness.state().is_unlocked());

    // Add the Task 4 login.
    harness.get_by_label("New login").click();
    harness.run();
    type_into(&mut harness, "Title", ROW_TITLE);
    type_into(&mut harness, "Username", USERNAME);
    type_into(&mut harness, "Web address", URL);
    type_into(&mut harness, "Password", SECRET);
    harness.get_by_label("Save").click();
    harness.step();
    run_until(&mut harness, kind_is(ScreenKind::Vault), WAIT);
    harness.run();
    let _ = harness.get_by_label(&format!("Username: {USERNAME}"));

    // Copy: one call to the secret clipboard, with the password.
    harness.get_by_label("Copy").click();
    harness.run();
    {
        let state = fake.0.borrow();
        assert_eq!(state.sets.len(), 1, "one set_secret call");
        assert_eq!(state.sets[0].as_str(), SECRET);
    }
    let _ = harness.get_by_label(messages::COPIED);

    // Lock with the button.
    harness.get_by_label("Lock").click();
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert!(!harness.state().is_unlocked());
    assert!(harness.state().secret_buffers_empty());

    // Quit: dropping the app releases the instance lock.
    drop(harness);

    // A new app on the same path starts on Unlock.
    let (app, _clock) = test_app_with_clipboard(dir, Box::new(fake.clone()));
    let mut harness = common::harness(app);
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    let _ = harness.get_by_label("Unlock");

    // A wrong password is refused with the fixed text.
    try_unlock(&mut harness, OTHER_PASSWORD);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert!(!harness.state().is_unlocked());
    let _ = harness.get_by_label(messages::WRONG_PASSWORD);

    // The right one opens it, and the login is there.
    try_unlock(&mut harness, PASSWORD);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    assert!(harness.state().is_unlocked());
    harness.get_by_label(ROW_TITLE).click();
    harness.run();
    let _ = harness.get_by_label(&format!("Username: {USERNAME}"));

    // Still exactly one clipboard write: opening and viewing copied nothing.
    assert_eq!(fake.0.borrow().sets.len(), 1);
    drop(harness);
}

#[test]
fn walking_skeleton_create_add_lock_unlock_see_item() {
    let dir = tempfile::tempdir().unwrap();
    run_flow(dir.path());
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn no_plaintext_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    run_flow(dir.path());

    let vault = vault_path(dir.path());
    let folder = vault.parent().unwrap();
    assert_eq!(folder.file_name().unwrap(), "Holm");

    // Exactly the vault and the lock file: no temps, nothing else.
    let mut names: Vec<String> = std::fs::read_dir(folder)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["holm.lock", "holm.vault"]);

    // Owner-only folder and files, all of them regular, the lock file empty.
    assert_eq!(mode(folder), 0o700);
    let lock = folder.join("holm.lock");
    for file in [&vault, &lock] {
        let meta = std::fs::symlink_metadata(file).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(mode(file), 0o600);
    }
    assert_eq!(std::fs::metadata(&lock).unwrap().len(), 0);

    // No item text and no password, in either file.
    for file in [&vault, &lock] {
        let bytes = std::fs::read(file).unwrap();
        for needle in [ROW_TITLE, USERNAME, URL_HOST, SECRET, PASSWORD] {
            assert!(
                !contains(&bytes, needle),
                "plaintext found on disk ({} bytes)",
                needle.len()
            );
        }
    }
}
