#![cfg(target_os = "macos")]
//! Recovery codes in the whole app: a field of that kind added in the login form, the
//! "{left} of {total} left" line, marking a code used, and copying one code. Driven
//! headless on a fresh vault. Every secret here is fake and contains `EXAMPLE`.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::{FakeClipboard, PASSWORD, harness, make_vault, run_until, test_app_with_clipboard};
use eframe::egui::{Event, Key, accesskit::Role};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use holm_core::settings::CLIPBOARD_DEFAULT_SECS;
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::messages;

const WAIT: Duration = Duration::from_secs(30);

const TITLE: &str = "Title";
const MAIL: &str = "Example Mail";
const CODES: &str = "EXAMPLE-code-1\nEXAMPLE-code-2\nEXAMPLE-code-3";

/// The field editor's boxes and pickers.
const FIELD_NAME: &str = "Field name";
const SUGGESTED: &str = "Suggested names";
const CODES_BOX: &str = "Recovery code list";
/// The kind option, and the code row's buttons.
const KIND_CODES: &str = "Recovery codes";
const COPY: &str = "Copy";
const MARK_USED: &str = "Mark used";
const MARK_UNUSED: &str = "Mark unused";

fn vault_screen(app: &HolmApp) -> bool {
    app.screen_kind() == ScreenKind::Vault
}

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

fn unlock(harness: &mut Harness<'static, HolmApp>) {
    type_into(harness, "Master password", PASSWORD);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(harness, vault_screen, WAIT);
    harness.run();
}

/// A fresh vault in `dir`, unlocked, with a fake clipboard. Nothing selected.
fn open(dir: &Path) -> (Harness<'static, HolmApp>, FakeClipboard) {
    make_vault(dir, PASSWORD);
    let fake = FakeClipboard::default();
    let (app, _clock) = test_app_with_clipboard(dir, Box::new(fake.clone()));
    let mut harness = harness(app);
    // Tall enough that the whole login form, with a custom row, fits on screen.
    harness.set_size(eframe::egui::vec2(1000.0, 1600.0));
    harness.run();
    unlock(&mut harness);
    (harness, fake)
}

fn click(harness: &mut Harness<'static, HolmApp>, label: &str) {
    // The form can be taller than the window; bring the target into view first.
    harness.get_by_label(label).scroll_to_me();
    harness.run();
    harness.get_by_label(label).click();
    harness.run();
}

fn count(harness: &Harness<'static, HolmApp>, label: &str) -> usize {
    harness.query_all_by_label(label).count()
}

/// Whether any accessibility node carries `needle` in a label, value or description.
fn in_accesskit(harness: &Harness<'static, HolmApp>, needle: &str) -> bool {
    harness.root().children_recursive().any(|node| {
        let access = node.accesskit_node();
        [access.label(), access.value(), access.description()]
            .iter()
            .flatten()
            .any(|t| t.contains(needle))
    })
}

fn is_text_box(role: Role) -> bool {
    matches!(
        role,
        Role::TextInput | Role::MultilineTextInput | Role::PasswordInput
    )
}

/// Clicks the last text box labelled `label` and types `text` into it.
fn type_into_last(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness
        .query_all_by_label(label)
        .rfind(|n| is_text_box(n.accesskit_node().role()))
        .expect("a text box")
        .scroll_to_me();
    harness.run();
    harness
        .query_all_by_label(label)
        .rfind(|n| is_text_box(n.accesskit_node().role()))
        .expect("a text box")
        .click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

/// Opens the new row's kind picker (the last combo box that is not the suggested
/// names) and picks "Recovery codes".
fn choose_codes_kind(harness: &mut Harness<'static, HolmApp>) {
    harness
        .query_all_by_role(Role::ComboBox)
        .rfind(|n| n.accesskit_node().label().as_deref() != Some(SUGGESTED))
        .expect("the new row's kind picker")
        .click();
    harness.run();
    click(harness, KIND_CODES);
}

/// Clicks the login form's Save and waits until the vault list is back.
fn save_form(harness: &mut Harness<'static, HolmApp>) {
    click(harness, "Save");
    let start = Instant::now();
    loop {
        harness.step();
        if vault_screen(harness.state()) && harness.query_by_label("Save").is_none() {
            break;
        }
        assert!(start.elapsed() < WAIT, "the save did not finish in time");
        std::thread::sleep(Duration::from_millis(10));
    }
    harness.run();
}

/// Steps until a label `label` is on screen. Panics after [`WAIT`].
fn wait_for_label(harness: &mut Harness<'static, HolmApp>, label: &str) {
    let start = Instant::now();
    loop {
        harness.step();
        if count(harness, label) > 0 {
            break;
        }
        assert!(start.elapsed() < WAIT, "`{label}` did not show in time");
        std::thread::sleep(Duration::from_millis(10));
    }
    harness.run();
}

/// A new login "Example Mail" with one "Backup" field of three recovery codes, saved
/// and left selected in the read-only view.
fn saved_codes(dir: &Path) -> (Harness<'static, HolmApp>, FakeClipboard) {
    let (mut harness, fake) = open(dir);
    common::new_login(&mut harness);
    harness.run();
    type_into(&mut harness, TITLE, MAIL);
    click(&mut harness, messages::ADD_FIELD);
    choose_codes_kind(&mut harness);
    type_into_last(&mut harness, FIELD_NAME, "Backup");
    type_into_last(&mut harness, CODES_BOX, CODES);
    save_form(&mut harness);
    (harness, fake)
}

#[test]
fn codes_save_and_show_count() {
    let dir = tempfile::tempdir().unwrap();
    let (harness, _fake) = saved_codes(dir.path());

    assert_eq!(count(&harness, "3 of 3 left"), 1);
    assert_eq!(count(&harness, "Backup"), 1);
    assert!(
        !in_accesskit(&harness, "EXAMPLE-code"),
        "no code is in an accessibility node"
    );
}

#[test]
fn mark_used_updates_the_count() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _fake) = saved_codes(dir.path());

    harness
        .get_all_by_label(MARK_USED)
        .next()
        .expect("a Mark used button")
        .click();
    harness.step();
    wait_for_label(&mut harness, "2 of 3 left");

    assert_eq!(count(&harness, "2 of 3 left"), 1);
    assert_eq!(count(&harness, MARK_UNUSED), 1);
    assert_eq!(count(&harness, MARK_USED), 2);
    assert!(!in_accesskit(&harness, "EXAMPLE-code"));
}

#[test]
fn copy_code_uses_the_clipboard() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, fake) = saved_codes(dir.path());
    assert!(fake.0.borrow().sets.is_empty());

    // The login's password Copy comes first; the code rows follow it.
    harness
        .get_all_by_label(COPY)
        .last()
        .expect("a code's Copy button")
        .click();
    harness.run();

    let state = fake.0.borrow();
    assert_eq!(state.sets.len(), 1, "one set call");
    assert!(state.sets[0].starts_with("EXAMPLE-code-"));
    drop(state);
    let _ = harness.get_by_label(messages::copied_note(CLIPBOARD_DEFAULT_SECS).as_str());
    assert!(harness.query_by_label(messages::COPY_FAILED).is_none());
    assert!(!in_accesskit(&harness, "EXAMPLE-code"));
}
