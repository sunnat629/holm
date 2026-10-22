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
fn every_type_is_listed() {
    let dir = tempfile::tempdir().unwrap();
    seed(
        dir.path(),
        vec![login("Example Mail"), crypto("Example Wallet")],
    );
    let (mut harness, _clock) = unlock(dir.path());
    assert_eq!(count(&harness, "Example Mail"), 1);
    assert_eq!(count(&harness, "Example Wallet"), 1);
    assert!(
        harness
            .query_by_label_contains("Other items not shown")
            .is_none()
    );
    type_into(&mut harness, "Search", "wallet");
    assert_eq!(count(&harness, "Example Wallet"), 1);
    assert_eq!(count(&harness, "Example Mail"), 0);
}

/// Closes T8 M5: a fresh unlock shows an empty Search box.
#[test]
fn search_field_empty_after_unlock() {
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path(), vec![login("Example Mail")]);
    let (mut harness, _clock) = unlock(dir.path());
    type_into(&mut harness, "Search", "mail");
    harness.get_by_label("Lock").click();
    harness.run();
    type_into(&mut harness, "Master password", PASSWORD);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(&mut harness, vault_screen, WAIT);
    harness.run();
    let value = harness.get_by_label("Search").value().unwrap_or_default();
    assert_eq!(value, "");
}

fn titled(n: usize) -> String {
    format!("Item {n:03}")
}

fn many(n: usize) -> Vec<ItemInput> {
    (0..n).map(|i| login(&titled(i))).collect()
}

/// The scroll bar's screen rect, from its accessibility node.
fn scroll_bar_rect(harness: &Harness<'static, HolmApp>) -> eframe::egui::Rect {
    use egui_kittest::kittest::NodeT;
    harness
        .root()
        .children_recursive()
        .find(|n| n.accesskit_node().role() == eframe::egui::accesskit::Role::ScrollBar)
        .map(|n| n.rect())
        .expect("a scroll bar node")
}

fn title_rect(harness: &Harness<'static, HolmApp>, title: &str) -> eframe::egui::Rect {
    harness.get_by_label(title).rect()
}

#[test]
fn scroll_bar_is_always_drawn() {
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path(), many(200));
    let (mut harness, _clock) = unlock(dir.path());
    harness.remove_cursor();
    harness.run();
    let bar = scroll_bar_rect(&harness);
    assert!(bar.width() > 0.0 && bar.height() > 0.0, "bar {bar:?}");
}

#[test]
fn list_scrolls_with_200_items() {
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path(), many(200));
    let (mut harness, _clock) = unlock(dir.path());
    let bar = scroll_bar_rect(&harness);
    // The list is height-bounded: it ends inside the screen, not at the content's end.
    let screen = harness.ctx.content_rect();
    assert!(
        bar.max.y <= screen.max.y + 0.5,
        "bar {bar:?} screen {screen:?}"
    );
    assert!(bar.height() < 1000.0, "bar is bounded by the panel");
    let first = titled(0);
    let last = titled(199);
    let in_view = |r: eframe::egui::Rect| r.max.y > bar.min.y && r.min.y < bar.max.y;
    assert!(in_view(title_rect(&harness, &first)));
    assert!(!in_view(title_rect(&harness, &last)));
    harness.hover_at(bar.center() - eframe::egui::vec2(40.0, 0.0));
    harness.run();
    for _ in 0..80 {
        harness.event(Event::MouseWheel {
            unit: eframe::egui::MouseWheelUnit::Point,
            delta: eframe::egui::vec2(0.0, -400.0),
            phase: eframe::egui::TouchPhase::Move,
            source: eframe::egui::MouseWheelSource::Wheel,
            modifiers: eframe::egui::Modifiers::NONE,
        });
        harness.run();
    }
    assert!(in_view(title_rect(&harness, &last)), "last visible");
    assert!(!in_view(title_rect(&harness, &first)), "first gone");
}

#[test]
fn count_line_counts_vault_not_search() {
    let dir = tempfile::tempdir().unwrap();
    seed(
        dir.path(),
        vec![
            login("Example Mail"),
            login("Example Bank"),
            login("Example Shop"),
            note("Example Note"),
        ],
    );
    let (mut harness, _clock) = unlock(dir.path());
    assert_eq!(count(&harness, "3 logins, 1 other item"), 1);
    type_into(&mut harness, "Search", "zzz");
    assert_eq!(count(&harness, "3 logins, 1 other item, 0 shown"), 1);
}

fn note(title: &str) -> ItemInput {
    ItemInput {
        title: Text::new(title.to_owned()),
        category: None,
        favourite: false,
        data: ItemData::SecureNote {
            body: SecretText::new("EXAMPLE body".to_owned()),
        },
    }
}
