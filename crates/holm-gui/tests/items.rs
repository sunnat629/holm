#![cfg(target_os = "macos")]
//! The item list and the login form, driven headless through the whole app.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use common::{PASSWORD, TestClock, harness, make_vault, run_until, test_app, vault_path};
use eframe::egui::{Event, Key, accesskit::Role};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use holm_core::settings::REHIDE_PASSWORD_SECS;
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::messages;

const WAIT: Duration = Duration::from_secs(30);
const TITLE: &str = "Title";
const USERNAME: &str = "Username";
const PASSWORD_FIELD: &str = "Password";
const SECRET: &str = "EXAMPLE-zq9-pass";
const ROW_TITLE: &str = "Example Mail";

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

fn vault_screen(app: &HolmApp) -> bool {
    app.screen_kind() == ScreenKind::Vault
}

/// A vault on disk, an app on it, unlocked and showing the (empty) list.
fn open(dir: &Path) -> (Harness<'static, HolmApp>, TestClock) {
    make_vault(dir, PASSWORD);
    reopen(dir)
}

/// An app on the vault already in `dir`, unlocked.
fn reopen(dir: &Path) -> (Harness<'static, HolmApp>, TestClock) {
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

fn fill_form(harness: &mut Harness<'static, HolmApp>, title: &str) {
    harness.get_by_label("New login").click();
    harness.run();
    if !title.is_empty() {
        type_into(harness, TITLE, title);
    }
    type_into(harness, USERNAME, "ada@example.com");
    type_into(harness, PASSWORD_FIELD, SECRET);
}

fn save_and_wait(harness: &mut Harness<'static, HolmApp>) {
    harness.get_by_label("Save").click();
    harness.step();
    assert!(
        harness.state().secret_buffers_empty(),
        "the form is wiped as the job leaves"
    );
    run_until(harness, vault_screen, WAIT);
    harness.run();
}

fn count(harness: &Harness<'static, HolmApp>, label: &str) -> usize {
    harness.query_all_by_label(label).count()
}

/// How many accessibility nodes carry `needle` in a label, value or description.
fn nodes_with(harness: &Harness<'static, HolmApp>, needle: &str) -> Vec<Role> {
    let mut roles = Vec::new();
    for node in harness.root().children_recursive() {
        let access = node.accesskit_node();
        let texts = [access.label(), access.value(), access.description()];
        if texts.iter().flatten().any(|t| t.contains(needle)) {
            roles.push(access.role());
        }
    }
    roles
}

fn add_example(harness: &mut Harness<'static, HolmApp>) {
    fill_form(harness, ROW_TITLE);
    save_and_wait(harness);
}

#[test]
fn add_login_shows_in_list() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    let _ = harness.get_by_label(messages::SELECT_OR_ADD);
    add_example(&mut harness);
    // The list row and the detail heading.
    assert_eq!(count(&harness, ROW_TITLE), 2);
    let _ = harness.get_by_label("Username: ada@example.com");
    assert!(nodes_with(&harness, SECRET).is_empty());
    assert!(harness.state().secret_buffers_empty());
}

#[test]
fn empty_title_shows_field_error() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    fill_form(&mut harness, "");
    harness.get_by_label("Save").click();
    harness.run();
    let _ = harness.get_by_label(messages::TITLE_EMPTY);
    // The form is still open with the typed values kept.
    assert!(!harness.state().secret_buffers_empty());
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
}

#[test]
fn edit_changes_title_and_keeps_password() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    add_example(&mut harness);
    harness.get_by_label("Edit").click();
    harness.run();
    harness.get_by_label(TITLE).click();
    harness.run();
    harness.key_press(Key::End);
    harness.event(Event::Text(" 2".to_owned()));
    harness.run();
    save_and_wait(&mut harness);
    assert_eq!(count(&harness, "Example Mail 2"), 2);
    harness.get_by_label("Reveal").click();
    harness.run();
    assert_eq!(nodes_with(&harness, SECRET).len(), 1);
}

#[test]
fn double_save_with_failing_store_adds_one_item() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    let folder = vault_path(dir.path()).parent().unwrap().to_owned();
    // A folder open to other users makes every write fail.
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o777)).unwrap();
    fill_form(&mut harness, ROW_TITLE);
    save_and_wait(&mut harness);
    let _ = harness.get_by_label(messages::DIR_PERMISSIONS);
    assert_eq!(count(&harness, ROW_TITLE), 1, "in memory, in the list once");

    // Retrying while it still fails changes nothing and adds nothing.
    harness.get_by_label("Try again").click();
    run_until(&mut harness, vault_screen, WAIT);
    harness.run();
    let _ = harness.get_by_label(messages::DIR_PERMISSIONS);
    assert_eq!(count(&harness, ROW_TITLE), 1);

    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
    harness.get_by_label("Try again").click();
    run_until(&mut harness, vault_screen, WAIT);
    harness.run();
    assert!(harness.query_by_label(messages::DIR_PERMISSIONS).is_none());
    assert!(harness.query_by_label("Try again").is_none());
    assert_eq!(count(&harness, ROW_TITLE), 1);

    // On disk too: a fresh app sees exactly one.
    drop(harness);
    let (harness, _clock) = reopen(dir.path());
    assert_eq!(count(&harness, ROW_TITLE), 1);
}

#[test]
fn save_banner_and_retry_survive_navigation() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    let folder = vault_path(dir.path()).parent().unwrap().to_owned();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o777)).unwrap();
    fill_form(&mut harness, ROW_TITLE);
    save_and_wait(&mut harness);
    let _ = harness.get_by_label(messages::DIR_PERMISSIONS);
    let _ = harness.get_by_label("Try again");

    // New login: the session is still dirty, so the banner stays.
    harness.get_by_label("New login").click();
    harness.run();
    let _ = harness.get_by_label(messages::DIR_PERMISSIONS);
    let _ = harness.get_by_label("Try again");

    // Selecting the row: same.
    harness.get_all_by_label(ROW_TITLE).next().unwrap().click();
    harness.run();
    let _ = harness.get_by_label(messages::DIR_PERMISSIONS);
    let _ = harness.get_by_label("Try again");

    // Edit: same.
    harness.get_by_label("Edit").click();
    harness.run();
    let _ = harness.get_by_label(messages::DIR_PERMISSIONS);
    let _ = harness.get_by_label("Try again");
}

#[test]
fn no_node_holds_password_while_hidden() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    fill_form(&mut harness, ROW_TITLE);
    // While typing, the form's field publishes no value.
    assert!(nodes_with(&harness, SECRET).is_empty());
    save_and_wait(&mut harness);
    assert!(nodes_with(&harness, SECRET).is_empty());
    harness.get_by_label("Edit").click();
    harness.run();
    assert!(nodes_with(&harness, SECRET).is_empty());
}

#[test]
fn reveal_leaks_only_in_label() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    add_example(&mut harness);
    harness.get_by_label("Reveal").click();
    harness.run();
    assert!(harness.state().secret_buffers_empty());
    assert_eq!(nodes_with(&harness, SECRET), [Role::Label]);
}

#[test]
fn reveal_shows_then_hides_after_rehide_secs() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock) = open(dir.path());
    add_example(&mut harness);
    harness.get_by_label("Reveal").click();
    harness.run();
    assert_eq!(nodes_with(&harness, SECRET).len(), 1);
    clock.advance(Duration::from_secs(u64::from(REHIDE_PASSWORD_SECS) - 1));
    harness.run();
    assert_eq!(nodes_with(&harness, SECRET).len(), 1, "still within time");
    clock.advance(Duration::from_secs(2));
    harness.run();
    assert!(nodes_with(&harness, SECRET).is_empty());
    let _ = harness.get_by_label("Reveal");
}

#[test]
fn reveal_hides_on_focus_loss() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    add_example(&mut harness);
    harness.get_by_label("Reveal").click();
    harness.run();
    assert_eq!(nodes_with(&harness, SECRET).len(), 1);
    let viewport = harness
        .input_mut()
        .viewports
        .get_mut(&eframe::egui::ViewportId::ROOT)
        .unwrap();
    viewport.focused = Some(false);
    harness.run();
    assert!(nodes_with(&harness, SECRET).is_empty());
}
