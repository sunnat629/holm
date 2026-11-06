#![cfg(target_os = "macos")]
//! The toolbar's "New" menu: a create form for each item kind. Driven headless on a
//! fresh vault. Every secret here is fake and contains `EXAMPLE`.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::{FakeClipboard, PASSWORD, harness, make_vault, run_until, test_app_with_clipboard};
use eframe::egui::{Event, Key};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use holm_core::rules::{Field, FieldError};
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::messages;

const WAIT: Duration = Duration::from_secs(30);

const ADDRESS: &str = "EXAMPLE-address-123";
const PHRASE: &str = "EXAMPLE alpha beta gamma";

fn vault_screen(app: &HolmApp) -> bool {
    app.screen_kind() == ScreenKind::Vault
}

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

fn open(dir: &Path) -> Harness<'static, HolmApp> {
    make_vault(dir, PASSWORD);
    let (app, _clock) = test_app_with_clipboard(dir, Box::new(FakeClipboard::default()));
    let mut harness = harness(app);
    harness.set_size(eframe::egui::vec2(1000.0, 1600.0));
    harness.run();
    type_into(&mut harness, "Master password", PASSWORD);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(&mut harness, vault_screen, WAIT);
    harness.run();
    harness
}

fn click(harness: &mut Harness<'static, HolmApp>, label: &str) {
    harness.get_by_label(label).scroll_to_me();
    harness.run();
    harness.get_by_label(label).click();
    harness.run();
}

/// Opens the New menu and picks `entry`.
fn new_item(harness: &mut Harness<'static, HolmApp>, entry: &str) {
    click(harness, "New");
    click(harness, entry);
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

#[test]
fn new_crypto_address_saves_and_hides_the_address() {
    let dir = tempfile::tempdir().unwrap();
    let mut harness = open(dir.path());
    new_item(&mut harness, "Crypto address");
    type_into(&mut harness, "Title", "Example Wallet");
    type_into(&mut harness, "Chain", "Bitcoin");
    type_into(&mut harness, "Address", ADDRESS);
    assert!(!in_accesskit(&harness, ADDRESS), "masked while typing");
    save_form(&mut harness);

    assert!(count(&harness, "Example Wallet") > 0, "listed");
    assert!(
        !in_accesskit(&harness, ADDRESS),
        "hidden in the detail view"
    );
}

#[test]
fn new_recovery_phrase_is_masked_and_saved() {
    let dir = tempfile::tempdir().unwrap();
    let mut harness = open(dir.path());
    new_item(&mut harness, "Recovery phrase");
    type_into(&mut harness, "Title", "Example Phrase");
    type_into(&mut harness, "Recovery phrase", PHRASE);
    assert!(!in_accesskit(&harness, PHRASE), "masked while typing");
    save_form(&mut harness);

    assert!(count(&harness, "Example Phrase") > 0, "listed");
    assert!(!in_accesskit(&harness, PHRASE));
}

#[test]
fn new_secure_note_saves() {
    let dir = tempfile::tempdir().unwrap();
    let mut harness = open(dir.path());
    new_item(&mut harness, "Secure note");
    type_into(&mut harness, "Title", "Example Note");
    type_into(&mut harness, "Note", "EXAMPLE note body");
    assert!(!in_accesskit(&harness, "EXAMPLE note body"));
    save_form(&mut harness);

    assert!(count(&harness, "Example Note") > 0, "listed");
}

#[test]
fn empty_phrase_shows_the_error_and_keeps_the_form() {
    let dir = tempfile::tempdir().unwrap();
    let mut harness = open(dir.path());
    new_item(&mut harness, "Recovery phrase");
    type_into(&mut harness, "Title", "Example Phrase");
    click(&mut harness, "Save");
    harness.run();

    let line = messages::field_error(&FieldError::Empty(Field::Phrase));
    assert_eq!(count(&harness, line), 1, "the phrase-empty line shows");
    assert_eq!(count(&harness, "Save"), 1, "the form stays open");
}
