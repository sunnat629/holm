#![cfg(target_os = "macos")]
//! Custom fields in the whole app: the detail rows, reveal, copy and its clear, the
//! label suggestions in the login form, a login edit that keeps the fields, dates, and
//! the "Edit fields" editor on a non-login item. Driven headless on a vault seeded
//! through the core. Every secret here is fake and contains `EXAMPLE`; no other text on
//! screen does.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::{
    FakeClipboard, PASSWORD, TestClock, harness, make_vault, run_until, test_app_with_clipboard,
    vault_path,
};
use eframe::egui::{Event, Key, Modifiers, OutputCommand, Shape, ViewportId, accesskit::Role};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use holm_core::clock::SystemClock;
use holm_core::fields::{CustomField, FieldValue, parse_date, try_field};
use holm_core::item::{ItemData, ItemId, ItemInput};
use holm_core::session::Session;
use holm_core::settings::REHIDE_PASSWORD_SECS;
use holm_core::text::{SecretText, Text};
use holm_crypto::MasterPassword;
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::messages;
use holm_platform::fs_store::FsStore;

const WAIT: Duration = Duration::from_secs(30);

const LOGIN: &str = "Example Server";
const RENAMED: &str = "Example Server Two";
const NOTE: &str = "Example Note";

const SECRET: &str = "EXAMPLE-field-secret";
const LOGIN_PASSWORD: &str = "EXAMPLE-login-pass";
const NOTE_BODY: &str = "EXAMPLE-note-body";
const DATE: &str = "2026-11-05";
const REMINDER: &str = "2026-10-29";
const ACCOUNT: &str = "public-account";

/// How a hidden field looks (the item view's `DOTS`).
const DOTS: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";
/// The custom row's buttons (the item view's `REVEAL_LABEL` and `COPY_LABEL`).
const REVEAL: &str = "Reveal";
const COPY: &str = "Copy";
/// The field editor's boxes and pickers.
const FIELD_NAME: &str = "Field name";
const SUGGESTED: &str = "Suggested names";
const VALUE: &str = "Value";

fn field(label: &str, value: FieldValue, expiry: Option<&str>) -> CustomField {
    try_field(
        Text::new(label.to_owned()),
        value,
        expiry.map(|d| parse_date(d).expect("a valid date")),
    )
    .expect("a valid field")
}

fn secret(s: &str) -> SecretText {
    SecretText::new(s.to_owned())
}

/// A vault in `dir` with a login holding one custom secret, and a secure note holding a
/// secret with a reminder, a date and a text field. Returns the login's id.
fn seed(dir: &Path) -> ItemId {
    make_vault(dir, PASSWORD);
    let mut session = Session::new(FsStore::new(vault_path(dir)), Box::new(SystemClock::new()));
    session
        .unlock(&MasterPassword::new(PASSWORD.to_owned()))
        .unwrap();
    let login = ItemInput {
        fields: vec![field("PIN", FieldValue::Secret(secret(SECRET)), None)],
        title: Text::new(LOGIN.to_owned()),
        category: None,
        favourite: false,
        data: ItemData::Login {
            username: Text::new("ada@example.com".to_owned()),
            password: secret(LOGIN_PASSWORD),
            urls: Vec::new(),
            notes: secret(""),
        },
    };
    let note = ItemInput {
        fields: vec![
            field("PIN", FieldValue::Secret(secret(SECRET)), Some(REMINDER)),
            field(
                "Renewal",
                FieldValue::Date(parse_date(DATE).expect("a valid date")),
                None,
            ),
            field(
                "Account",
                FieldValue::Text(Text::new(ACCOUNT.to_owned())),
                None,
            ),
        ],
        title: Text::new(NOTE.to_owned()),
        category: None,
        favourite: false,
        data: ItemData::SecureNote {
            body: secret(NOTE_BODY),
        },
    };
    let id = session.add_item(login).unwrap();
    session.add_item(note).unwrap();
    id
}

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

fn vault_screen(app: &HolmApp) -> bool {
    app.screen_kind() == ScreenKind::Vault
}

fn unlock(harness: &mut Harness<'static, HolmApp>) {
    type_into(harness, "Master password", PASSWORD);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(harness, vault_screen, WAIT);
    harness.run();
}

/// The seeded vault, unlocked, with a fake clipboard. Nothing selected.
fn open(dir: &Path) -> (Harness<'static, HolmApp>, TestClock, FakeClipboard, ItemId) {
    let id = seed(dir);
    let fake = FakeClipboard::default();
    let (app, clock) = test_app_with_clipboard(dir, Box::new(fake.clone()));
    let mut harness = harness(app);
    // Tall enough that the whole login form, with two custom rows, fits on screen.
    harness.set_size(eframe::egui::vec2(1000.0, 1600.0));
    harness.run();
    unlock(&mut harness);
    (harness, clock, fake, id)
}

/// Clicks the list row titled `title`.
fn select(harness: &mut Harness<'static, HolmApp>, title: &str) {
    harness.get_all_by_label(title).next().unwrap().click();
    harness.run();
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

/// Every accessibility node carrying `needle` in a label, value or description.
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

/// Whether any text painted in the last frame contains `needle`.
fn painted(harness: &Harness<'static, HolmApp>, needle: &str) -> bool {
    harness
        .output()
        .shapes
        .iter()
        .any(|clipped| shape_has(&clipped.shape, needle))
}

fn shape_has(shape: &Shape, needle: &str) -> bool {
    match shape {
        Shape::Text(t) => t.galley.text().contains(needle),
        Shape::Vec(shapes) => shapes.iter().any(|s| shape_has(s, needle)),
        _ => false,
    }
}

/// The last text Holm put on the clipboard, if it still holds it.
fn clipboard_holds(fake: &FakeClipboard) -> Option<String> {
    fake.0.borrow().contents.clone()
}

fn set_focused(harness: &mut Harness<'static, HolmApp>, focused: bool) {
    harness
        .input_mut()
        .viewports
        .get_mut(&ViewportId::ROOT)
        .unwrap()
        .focused = Some(focused);
    harness.run();
}

/// Clicks the last text box labelled `label`, selects all of it and types `text`.
fn replace_last(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness
        .query_all_by_label(label)
        .rfind(|n| n.accesskit_node().role() == Role::TextInput)
        .expect("a text box")
        .scroll_to_me();
    harness.run();
    harness
        .query_all_by_label(label)
        .rfind(|n| n.accesskit_node().role() == Role::TextInput)
        .expect("a text box")
        .click();
    harness.run();
    harness.key_press_modifiers(Modifiers::COMMAND, Key::A);
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

/// The value of the last text box labelled `label`.
fn last_value(harness: &Harness<'static, HolmApp>, label: &str) -> Option<String> {
    harness
        .query_all_by_label(label)
        .rfind(|n| n.accesskit_node().role() == Role::TextInput)
        .and_then(|n| n.accesskit_node().value())
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

#[test]
fn custom_secret_hidden_until_reveal() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake, _id) = open(dir.path());
    select(&mut harness, NOTE);
    let _ = harness.get_by_label("PIN");
    assert_eq!(count(&harness, DOTS), 2, "the body and the custom secret");
    assert!(!painted(&harness, SECRET));

    click(&mut harness, REVEAL);
    assert!(painted(&harness, SECRET), "paint_secret drew it");
    assert_eq!(count(&harness, DOTS), 1, "only the body stays hidden");
    assert!(!painted(&harness, NOTE_BODY));
}

#[test]
fn custom_secret_not_in_accesskit() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake, _id) = open(dir.path());
    select(&mut harness, NOTE);
    assert!(nodes_with(&harness, "EXAMPLE").is_empty(), "hidden");
    let _ = harness.get_by_role_and_label(Role::Button, REVEAL);
    assert!(
        nodes_with(&harness, "PIN")
            .iter()
            .all(|role| *role != Role::Button),
        "the user's label is never a button name"
    );

    click(&mut harness, REVEAL);
    assert!(painted(&harness, SECRET));
    assert!(nodes_with(&harness, "EXAMPLE").is_empty(), "revealed");
}

#[test]
fn custom_copy_sets_pending_clear() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock, fake, _id) = open(dir.path());
    select(&mut harness, NOTE);
    harness.get_by_label(COPY).click();
    for _ in 0..4 {
        harness.step();
        assert!(
            !harness
                .output()
                .platform_output
                .commands
                .iter()
                .any(|c| matches!(c, OutputCommand::CopyText(_))),
            "egui's copy_text is never used"
        );
    }
    harness.run();
    assert_eq!(clipboard_holds(&fake).as_deref(), Some(SECRET));
    assert!(!painted(&harness, SECRET), "a copy does not reveal");

    clock.advance(Duration::from_secs(u64::from(REHIDE_PASSWORD_SECS) + 1));
    harness.run();
    assert_eq!(clipboard_holds(&fake), None, "the copy is cleared on time");
}

#[test]
fn reveal_hides_after_30s() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock, _fake, _id) = open(dir.path());
    select(&mut harness, NOTE);

    click(&mut harness, REVEAL);
    clock.advance(Duration::from_secs(u64::from(REHIDE_PASSWORD_SECS) - 1));
    harness.run();
    assert!(painted(&harness, SECRET), "still shows at 29 s");
    clock.advance(Duration::from_secs(1));
    harness.run();
    assert!(!painted(&harness, SECRET), "hidden at 30 s");

    click(&mut harness, REVEAL);
    assert!(painted(&harness, SECRET));
    set_focused(&mut harness, false);
    assert!(!painted(&harness, SECRET), "hidden on blur");
    set_focused(&mut harness, true);
    assert!(!painted(&harness, SECRET), "stays hidden on focus");
}

#[test]
fn text_field_shows_secret_hint() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake, _id) = open(dir.path());
    select(&mut harness, LOGIN);
    click(&mut harness, "Edit");
    click(&mut harness, messages::ADD_FIELD);
    assert_eq!(
        count(&harness, messages::TEXT_FIELD_HINT),
        1,
        "a new Text field says to use a Secret field for sensitive values"
    );
}

#[test]
fn label_suggestion_fills_and_free_text_stays() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake, _id) = open(dir.path());
    select(&mut harness, LOGIN);
    click(&mut harness, "Edit");
    click(&mut harness, messages::ADD_FIELD);

    harness
        .query_all_by_label(SUGGESTED)
        .rfind(|n| n.accesskit_node().role() == Role::ComboBox)
        .expect("the new row's picker")
        .click();
    harness.run();
    click(&mut harness, "Recovery code");
    assert_eq!(
        last_value(&harness, FIELD_NAME).as_deref(),
        Some("Recovery code"),
        "the suggestion fills the box"
    );

    replace_last(&mut harness, FIELD_NAME, "Backup code");
    assert_eq!(
        last_value(&harness, FIELD_NAME).as_deref(),
        Some("Backup code")
    );
    replace_last(&mut harness, VALUE, ACCOUNT);
    save_form(&mut harness);

    select(&mut harness, LOGIN);
    assert_eq!(count(&harness, "Backup code"), 1, "free text is saved");
    assert_eq!(count(&harness, "Recovery code"), 0);
    assert_eq!(count(&harness, ACCOUNT), 1);
    assert_eq!(count(&harness, "PIN"), 1, "the stored field stays");
}

#[test]
fn login_edit_keeps_custom_fields() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake, id) = open(dir.path());
    select(&mut harness, LOGIN);
    click(&mut harness, "Edit");
    replace_last(&mut harness, "Title", RENAMED);
    save_form(&mut harness);

    select(&mut harness, RENAMED);
    assert_eq!(count(&harness, "PIN"), 1);
    // The login password's Reveal comes first, the custom row's second.
    harness.get_all_by_label(REVEAL).nth(1).unwrap().click();
    harness.run();
    assert!(
        painted(&harness, SECRET),
        "the custom secret is still there"
    );
    assert!(nodes_with(&harness, "EXAMPLE").is_empty());

    // On disk too: the app's session goes first.
    drop(harness);
    let mut session = Session::new(
        FsStore::new(vault_path(dir.path())),
        Box::new(SystemClock::new()),
    );
    session
        .unlock(&MasterPassword::new(PASSWORD.to_owned()))
        .unwrap();
    let item = session.open_item(id).unwrap();
    assert_eq!(item.title(), RENAMED);
    assert_eq!(item.fields().len(), 1);
    assert_eq!(item.fields()[0].label(), "PIN");
    assert!(matches!(
        item.fields()[0].value(),
        FieldValue::Secret(s) if s.expose() == SECRET
    ));
}

#[test]
fn date_field_shows_iso() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake, _id) = open(dir.path());
    select(&mut harness, NOTE);
    assert_eq!(count(&harness, DATE), 1);
    assert_eq!(count(&harness, "Renewal"), 1);
    assert_eq!(count(&harness, messages::REMIND_ON), 1);
    assert_eq!(count(&harness, REMINDER), 1);
    assert!(nodes_with(&harness, "EXAMPLE").is_empty());
}

#[test]
fn edit_fields_on_a_note_saves_to_disk() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake, _id) = open(dir.path());
    select(&mut harness, NOTE);
    click(&mut harness, messages::EDIT_FIELDS);
    click(&mut harness, messages::ADD_FIELD);
    replace_last(&mut harness, FIELD_NAME, "Locker");
    replace_last(&mut harness, VALUE, "public-locker");
    save_form(&mut harness);

    select(&mut harness, NOTE);
    assert_eq!(count(&harness, "Locker"), 1);
    assert_eq!(count(&harness, "public-locker"), 1);
    assert_eq!(count(&harness, "Renewal"), 1, "the old field stays");
    assert!(nodes_with(&harness, "EXAMPLE").is_empty());

    // On disk too: the app's session goes first.
    drop(harness);
    let mut session = Session::new(
        FsStore::new(vault_path(dir.path())),
        Box::new(SystemClock::new()),
    );
    session
        .unlock(&MasterPassword::new(PASSWORD.to_owned()))
        .unwrap();
    let note_id = session
        .active_entries()
        .unwrap()
        .find(|e| e.title() == NOTE)
        .expect("the note")
        .id();
    let note = session.open_item(note_id).unwrap();
    let labels: Vec<&str> = note.fields().iter().map(CustomField::label).collect();
    assert_eq!(
        labels,
        ["PIN", "Renewal", "Account", "Locker"],
        "order kept, new one last"
    );
}
