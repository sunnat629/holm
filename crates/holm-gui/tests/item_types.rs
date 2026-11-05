#![cfg(target_os = "macos")]
//! The four item types in the list and in their detail views: crypto addresses,
//! recovery phrases and secure notes next to logins. Driven headless through the whole
//! app on a vault seeded through the core. Every secret here is fake and contains
//! `EXAMPLE`; no other text on screen does.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{
    FakeClipboard, OTHER_PASSWORD, PASSWORD, TestClock, harness, make_vault, run_until,
    test_app_with_clipboard, vault_path,
};
use eframe::egui::{Event, Key, Shape, ViewportId, accesskit::Role};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use holm_core::clock::SystemClock;
use holm_core::item::{ItemData, ItemInput};
use holm_core::session::Session;
use holm_core::settings::{REHIDE_PASSWORD_SECS, REHIDE_PHRASE_SECS};
use holm_core::text::{GatedSecret, SecretText, Text};
use holm_crypto::MasterPassword;
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::messages;
use holm_platform::fs_store::FsStore;

const WAIT: Duration = Duration::from_secs(30);

const LOGIN: &str = "Example Mail";
const WALLET: &str = "Example Wallet";
const PHRASE: &str = "Example Phrase";
const NOTE: &str = "Example Note";

const LOGIN_PASSWORD: &str = "EXAMPLE-login-pass";
const LOGIN_NOTES: &str = "EXAMPLE-login-notes";
const CHAIN: &str = "Test chain";
const ADDRESS: &str = "EXAMPLE-0xaddr";
const MEMO: &str = "EXAMPLE-memo";
const WALLET_NOTES: &str = "EXAMPLE-wallet-notes";
const WORDS: &str = "EXAMPLE alpha bravo charlie delta";
const PHRASE_NOTES: &str = "EXAMPLE-phrase-notes";
const BODY_ONE: &str = "EXAMPLE first line";
const BODY_TWO: &str = "EXAMPLE second line";

fn input(title: &str, data: ItemData) -> ItemInput {
    ItemInput {
        fields: Vec::new(),
        title: Text::new(title.to_owned()),
        category: None,
        favourite: false,
        data,
    }
}

fn secret(s: &str) -> SecretText {
    SecretText::new(s.to_owned())
}

/// A vault in `dir` holding one item of each type, added through the core.
fn seed(dir: &Path) {
    make_vault(dir, PASSWORD);
    let mut session = Session::new(FsStore::new(vault_path(dir)), Box::new(SystemClock::new()));
    session
        .unlock(&MasterPassword::new(PASSWORD.to_owned()))
        .unwrap();
    let items = [
        input(
            LOGIN,
            ItemData::Login {
                username: Text::new("ada@example.com".to_owned()),
                password: secret(LOGIN_PASSWORD),
                urls: Vec::new(),
                notes: secret(LOGIN_NOTES),
            },
        ),
        input(
            WALLET,
            ItemData::CryptoAddress {
                chain: Text::new(CHAIN.to_owned()),
                address: secret(ADDRESS),
                memo: secret(MEMO),
                notes: secret(WALLET_NOTES),
            },
        ),
        input(
            PHRASE,
            ItemData::RecoveryPhrase {
                phrase: GatedSecret::new(secret(WORDS)),
                notes: secret(PHRASE_NOTES),
            },
        ),
        input(
            NOTE,
            ItemData::SecureNote {
                body: secret(&format!("{BODY_ONE}\n{BODY_TWO}")),
            },
        ),
    ];
    for item in items {
        session.add_item(item).unwrap();
    }
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
fn open(dir: &Path) -> (Harness<'static, HolmApp>, TestClock, FakeClipboard) {
    seed(dir);
    let fake = FakeClipboard::default();
    let (app, clock) = test_app_with_clipboard(dir, Box::new(fake.clone()));
    let mut harness = harness(app);
    harness.run();
    unlock(&mut harness);
    (harness, clock, fake)
}

/// Clicks the list row titled `title`.
fn select(harness: &mut Harness<'static, HolmApp>, title: &str) {
    harness.get_all_by_label(title).next().unwrap().click();
    harness.run();
}

fn click(harness: &mut Harness<'static, HolmApp>, label: &str) {
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

/// How many text edits are on screen.
fn text_edits(harness: &Harness<'static, HolmApp>) -> usize {
    harness
        .root()
        .children_recursive()
        .filter(|n| {
            matches!(
                n.accesskit_node().role(),
                Role::TextInput | Role::MultilineTextInput
            )
        })
        .count()
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

/// Opens the phrase gate, types `password` and waits for the worker to answer.
fn try_phrase(harness: &mut Harness<'static, HolmApp>, password: &str) {
    if harness
        .query_by_label(messages::PHRASE_PASSWORD_LABEL)
        .is_none()
    {
        click(harness, "Reveal\u{2026}");
    }
    type_into(harness, messages::PHRASE_PASSWORD_LABEL, password);
    harness.key_press(Key::Enter);
    harness.step();
    assert!(
        harness.state().secret_buffers_empty(),
        "the gate's password is wiped as the job leaves"
    );
    run_until(harness, vault_screen, WAIT);
    harness.run();
}

/// Selects the phrase item and reveals it with the right password.
fn reveal_phrase(harness: &mut Harness<'static, HolmApp>) {
    select(harness, PHRASE);
    try_phrase(harness, PASSWORD);
    assert!(painted(harness, WORDS), "the phrase shows");
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

#[test]
fn list_shows_all_four_types_with_subtitles() {
    let dir = tempfile::tempdir().unwrap();
    let (harness, _clock, _fake) = open(dir.path());
    for title in [LOGIN, WALLET, PHRASE, NOTE] {
        assert_eq!(count(&harness, title), 1, "{title} is in the list");
    }
    for subtitle in ["ada@example.com", CHAIN, "Recovery phrase", "Secure note"] {
        assert_eq!(count(&harness, subtitle), 1, "subtitle {subtitle}");
    }
    assert!(harness.query_by_label_contains("not shown here").is_none());
}

#[test]
fn crypto_reveal_and_copy_address() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock, fake) = open(dir.path());
    select(&mut harness, WALLET);
    let _ = harness.get_by_label(&format!("Chain: {CHAIN}"));
    assert!(!painted(&harness, ADDRESS));

    click(&mut harness, "Reveal address");
    assert!(painted(&harness, ADDRESS));
    assert!(!painted(&harness, MEMO), "only the address shows");
    assert!(nodes_with(&harness, "EXAMPLE").is_empty());

    click(&mut harness, "Copy address");
    assert_eq!(clipboard_holds(&fake).as_deref(), Some(ADDRESS));

    click(&mut harness, "Reveal memo");
    assert!(painted(&harness, MEMO));
    assert!(!painted(&harness, ADDRESS), "one field shows at a time");
    click(&mut harness, "Copy notes");
    assert_eq!(clipboard_holds(&fake).as_deref(), Some(WALLET_NOTES));

    clock.advance(Duration::from_secs(u64::from(REHIDE_PASSWORD_SECS) + 1));
    harness.run();
    assert!(!painted(&harness, MEMO), "hidden after 31 s");
    assert!(!painted(&harness, ADDRESS));
    assert_eq!(clipboard_holds(&fake), None, "the copy is cleared on time");
}

#[test]
fn note_reveal_multiline_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock, fake) = open(dir.path());
    select(&mut harness, NOTE);
    assert!(!painted(&harness, BODY_ONE));

    let edits_before = text_edits(&harness);
    click(&mut harness, "Reveal note");
    let multi = harness.output().shapes.iter().any(|c| match &c.shape {
        Shape::Text(t) => {
            let text = t.galley.text();
            text.contains(BODY_ONE) && text.contains(BODY_TWO) && t.galley.rows.len() >= 2
        }
        _ => false,
    });
    assert!(multi, "the body is painted on more than one line");
    assert!(nodes_with(&harness, "EXAMPLE").is_empty());
    assert_eq!(
        text_edits(&harness),
        edits_before,
        "no text edit holds the body (only the search box is one)"
    );

    click(&mut harness, "Copy note");
    assert_eq!(
        clipboard_holds(&fake).as_deref(),
        Some(format!("{BODY_ONE}\n{BODY_TWO}").as_str())
    );
    clock.advance(Duration::from_secs(u64::from(REHIDE_PASSWORD_SECS) + 1));
    harness.run();
    assert!(!painted(&harness, BODY_ONE));
    assert_eq!(clipboard_holds(&fake), None);
}

#[test]
fn phrase_needs_password_each_time() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake) = open(dir.path());
    select(&mut harness, PHRASE);
    assert!(!painted(&harness, WORDS));
    assert!(
        harness
            .query_by_label(messages::PHRASE_PASSWORD_LABEL)
            .is_none()
    );

    click(&mut harness, "Reveal\u{2026}");
    let field = harness.get_by_label(messages::PHRASE_PASSWORD_LABEL);
    assert_eq!(field.accesskit_node().role(), Role::PasswordInput);
    try_phrase(&mut harness, PASSWORD);
    assert!(painted(&harness, WORDS));
    assert!(
        harness
            .query_by_label(messages::PHRASE_PASSWORD_LABEL)
            .is_none()
    );

    click(&mut harness, "Hide");
    assert!(!painted(&harness, WORDS));
    click(&mut harness, "Reveal\u{2026}");
    assert!(!painted(&harness, WORDS), "a new reveal asks again");
    let _ = harness.get_by_label(messages::PHRASE_PASSWORD_LABEL);
    assert!(
        harness.state().secret_buffers_empty(),
        "the gate starts empty"
    );
    try_phrase(&mut harness, PASSWORD);
    assert!(painted(&harness, WORDS));
}

#[test]
fn phrase_wrong_password_throttled() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake) = open(dir.path());
    select(&mut harness, PHRASE);
    try_phrase(&mut harness, OTHER_PASSWORD);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    let _ = harness.get_by_label(messages::PHRASE_WRONG_PASSWORD);
    assert!(!painted(&harness, WORDS));
    assert_eq!(count(&harness, PHRASE), 2, "the item view is kept");

    try_phrase(&mut harness, OTHER_PASSWORD);
    try_phrase(&mut harness, OTHER_PASSWORD);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    assert!(harness.state().throttle_status().retry_after.is_some());
    assert!(!painted(&harness, WORDS));

    // Type a password so the field is not empty: only the throttle keeps the button off.
    type_into(&mut harness, messages::PHRASE_PASSWORD_LABEL, PASSWORD);
    assert!(
        harness
            .get_by_role_and_label(Role::Button, "Show phrase")
            .accesskit_node()
            .is_disabled(),
        "no try while the wait is due"
    );
    harness
        .get_by_role_and_label(Role::Button, "Show phrase")
        .click();
    harness.key_press(Key::Enter);
    harness.step();
    assert_eq!(
        harness.state().screen_kind(),
        ScreenKind::Vault,
        "no worker job started"
    );
    assert!(!painted(&harness, WORDS));
}

#[test]
fn phrase_hides_after_60s_blur_leave_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock, _fake) = open(dir.path());

    // On its timer.
    reveal_phrase(&mut harness);
    clock.advance(Duration::from_secs(u64::from(REHIDE_PHRASE_SECS) - 1));
    harness.run();
    assert!(painted(&harness, WORDS), "still within time");
    clock.advance(Duration::from_secs(2));
    harness.run();
    assert!(!painted(&harness, WORDS), "hidden after 60 s");
    assert!(harness.state().secret_buffers_empty());

    // On window blur.
    try_phrase(&mut harness, PASSWORD);
    assert!(painted(&harness, WORDS));
    set_focused(&mut harness, false);
    assert!(!painted(&harness, WORDS), "hidden on blur");
    set_focused(&mut harness, true);
    assert!(!painted(&harness, WORDS), "stays hidden on focus");

    // On selecting another item.
    try_phrase(&mut harness, PASSWORD);
    select(&mut harness, LOGIN);
    assert!(!painted(&harness, WORDS));
    select(&mut harness, PHRASE);
    assert!(!painted(&harness, WORDS), "hidden on leave");
    assert!(
        harness
            .query_by_label(messages::PHRASE_PASSWORD_LABEL)
            .is_none()
    );

    // On lock.
    try_phrase(&mut harness, PASSWORD);
    click(&mut harness, "Lock");
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert!(!painted(&harness, WORDS));
    unlock(&mut harness);
    select(&mut harness, PHRASE);
    assert!(!painted(&harness, WORDS), "hidden after lock");
}

#[test]
fn phrase_copy_only_while_revealed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock, fake) = open(dir.path());
    select(&mut harness, PHRASE);
    assert!(harness.query_by_label("Copy phrase").is_none());

    try_phrase(&mut harness, PASSWORD);
    click(&mut harness, "Copy phrase");
    assert_eq!(clipboard_holds(&fake).as_deref(), Some(WORDS));

    clock.advance(Duration::from_secs(u64::from(REHIDE_PHRASE_SECS) + 1));
    harness.run();
    assert!(!painted(&harness, WORDS));
    assert!(harness.query_by_label("Copy phrase").is_none());
    assert_eq!(clipboard_holds(&fake), None, "the copy is cleared on time");
}

#[test]
fn edit_hidden_for_non_login() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake) = open(dir.path());
    for title in [WALLET, PHRASE, NOTE] {
        select(&mut harness, title);
        assert!(harness.query_by_label("Edit").is_none(), "{title}");
        let _ = harness.get_by_label(messages::EDIT_IN_CLI);
    }
    select(&mut harness, LOGIN);
    let _ = harness.get_by_label("Edit");
    assert!(harness.query_by_label(messages::EDIT_IN_CLI).is_none());
}

#[test]
fn edit_hides_login_reveal() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake) = open(dir.path());
    select(&mut harness, LOGIN);
    click(&mut harness, "Reveal notes");
    assert!(painted(&harness, LOGIN_NOTES));
    click(&mut harness, "Edit");
    assert!(!painted(&harness, LOGIN_NOTES));
}

#[test]
fn search_finds_non_login_by_title() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake) = open(dir.path());
    type_into(&mut harness, "Search", "wallet");
    assert_eq!(count(&harness, WALLET), 1);
    for title in [LOGIN, PHRASE, NOTE] {
        assert_eq!(count(&harness, title), 0, "{title}");
    }
}

#[test]
fn views_hold_no_secret_in_accesskit() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, _fake) = open(dir.path());
    assert!(nodes_with(&harness, "EXAMPLE").is_empty(), "the list");
    for title in [LOGIN, WALLET, PHRASE, NOTE] {
        select(&mut harness, title);
        assert!(nodes_with(&harness, "EXAMPLE").is_empty(), "{title} hidden");
    }

    // Revealed fields other than the login password are painted, not published.
    select(&mut harness, LOGIN);
    click(&mut harness, "Reveal notes");
    assert!(nodes_with(&harness, "EXAMPLE").is_empty(), "login notes");
    select(&mut harness, WALLET);
    for label in ["Reveal address", "Reveal memo", "Reveal notes"] {
        click(&mut harness, label);
        assert!(nodes_with(&harness, "EXAMPLE").is_empty(), "{label}");
    }
    select(&mut harness, NOTE);
    click(&mut harness, "Reveal note");
    assert!(nodes_with(&harness, "EXAMPLE").is_empty(), "note body");

    // The gate's typed password and the revealed phrase stay out too.
    select(&mut harness, PHRASE);
    click(&mut harness, "Reveal\u{2026}");
    type_into(&mut harness, messages::PHRASE_PASSWORD_LABEL, PASSWORD);
    assert!(nodes_with(&harness, "EXAMPLE").is_empty(), "the gate");
    harness.key_press(Key::Enter);
    harness.step();
    run_until(&mut harness, vault_screen, WAIT);
    harness.run();
    assert!(painted(&harness, WORDS));
    assert!(nodes_with(&harness, "EXAMPLE").is_empty(), "the phrase");
    click(&mut harness, "Reveal notes");
    assert!(nodes_with(&harness, "EXAMPLE").is_empty(), "phrase notes");
}
