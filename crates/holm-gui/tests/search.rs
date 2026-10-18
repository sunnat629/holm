#![cfg(target_os = "macos")]
//! The search box, driven headless through the whole app.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{PASSWORD, TestClock, harness, make_vault, run_until, test_app, vault_path};
use eframe::egui::{Event, Key};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use holm_core::clock::SystemClock;
use holm_core::item::{ItemData, ItemInput};
use holm_core::session::Session;
use holm_core::text::{SecretText, Text};
use holm_crypto::MasterPassword;
use holm_gui::app::{HolmApp, ScreenKind};
use holm_platform::fs_store::FsStore;

const WAIT: Duration = Duration::from_secs(30);

fn login(title: &str) -> ItemInput {
    ItemInput {
        title: Text::new(title.to_owned()),
        category: None,
        favourite: false,
        data: ItemData::Login {
            username: Text::new("ada@example.com".to_owned()),
            password: SecretText::new("EXAMPLE-pass".to_owned()),
            urls: Vec::new(),
            notes: SecretText::new(String::new()),
        },
    }
}

fn crypto(title: &str) -> ItemInput {
    ItemInput {
        title: Text::new(title.to_owned()),
        category: None,
        favourite: false,
        data: ItemData::CryptoAddress {
            chain: Text::new("EXAMPLE-chain".to_owned()),
            address: SecretText::new("EXAMPLE-0xaddr".to_owned()),
            memo: SecretText::new(String::new()),
            notes: SecretText::new(String::new()),
        },
    }
}

/// A vault holding `items`, made straight through the core.
fn seed(dir: &Path, items: Vec<ItemInput>) {
    make_vault(dir, PASSWORD);
    let mut session = Session::new(FsStore::new(vault_path(dir)), Box::new(SystemClock::new()));
    session
        .unlock(&MasterPassword::new(PASSWORD.to_owned()))
        .unwrap();
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

fn unlock(dir: &Path) -> (Harness<'static, HolmApp>, TestClock) {
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

fn count(harness: &Harness<'static, HolmApp>, label: &str) -> usize {
    harness.query_all_by_label(label).count()
}

#[test]
fn search_box_filters_rows() {
    let dir = tempfile::tempdir().unwrap();
    seed(
        dir.path(),
        vec![
            login("Example Mail"),
            login("Example Bank"),
            login("Example Shop"),
        ],
    );
    let (mut harness, _clock) = unlock(dir.path());
    assert_eq!(count(&harness, "Example Mail"), 1);
    assert_eq!(count(&harness, "Example Bank"), 1);
    type_into(&mut harness, "Search", "mail");
    assert_eq!(count(&harness, "Example Mail"), 1);
    assert_eq!(count(&harness, "Example Bank"), 0);
    assert_eq!(count(&harness, "Example Shop"), 0);
}

#[test]
fn search_cleared_on_lock() {
    let dir = tempfile::tempdir().unwrap();
    seed(
        dir.path(),
        vec![login("Example Mail"), login("Example Bank")],
    );
    let (mut harness, _clock) = unlock(dir.path());
    type_into(&mut harness, "Search", "mail");
    assert_eq!(count(&harness, "Example Bank"), 0);
    harness.get_by_label("Lock").click();
    harness.run();
    type_into(&mut harness, "Master password", PASSWORD);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(&mut harness, vault_screen, WAIT);
    harness.run();
    assert_eq!(count(&harness, "Example Bank"), 1);
    assert_eq!(count(&harness, "Example Mail"), 1);
}

#[test]
fn other_types_count_line() {
    let dir = tempfile::tempdir().unwrap();
    seed(
        dir.path(),
        vec![login("Example Mail"), crypto("Example Wallet")],
    );
    let (harness, _clock) = unlock(dir.path());
    assert_eq!(count(&harness, "Example Wallet"), 0);
    let _ = harness.get_by_label("Other items not shown here: 1");
}
