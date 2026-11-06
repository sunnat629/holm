#![cfg(target_os = "macos")]
//! The list's expiry badge and the Expiring chip, driven headless through the app.
//!
//! "Today" is the UTC day of the shared `TestClock`, which is both the session clock
//! (the Expiring filter) and the UI clock (the badges).

mod common;

use std::path::Path;
use std::time::Duration;

use common::{PASSWORD, TestClock, harness, make_vault, run_until, test_app, vault_path};
use eframe::egui::{Event, Key, accesskit::Role, epaint::Shape};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use holm_core::category::CategoryId;
use holm_core::clock::{Clock, SystemClock};
use holm_core::fields::{
    CalendarDate, CustomField, FieldValue, epoch_day, from_unix_secs, try_field,
};
use holm_core::item::{ItemData, ItemInput};
use holm_core::rules::EXPIRING_WITHIN_DAYS;
use holm_core::session::Session;
use holm_core::text::{SecretText, Text};
use holm_crypto::MasterPassword;
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::messages::CHIP_EXPIRING;
use holm_platform::fs_store::FsStore;

const WAIT: Duration = Duration::from_secs(60);
const SECRET: &str = "EXAMPLE-field-secret";
const LABEL: &str = "renewal-reminder-label";

/// The UTC day of a fresh `TestClock`, which every test app starts from.
fn fake_today() -> CalendarDate {
    from_unix_secs(TestClock::new().now_unix().0).unwrap()
}

fn shift(today: CalendarDate, days: i64) -> CalendarDate {
    from_unix_secs((i64::from(epoch_day(today)) + days) * 86_400).unwrap()
}

fn field(expiry: Option<CalendarDate>) -> CustomField {
    try_field(
        Text::new(LABEL.to_owned()),
        FieldValue::Secret(SecretText::new(SECRET.to_owned())),
        expiry,
    )
    .unwrap()
}

fn work_id(session: &Session<FsStore>) -> CategoryId {
    session
        .categories()
        .unwrap()
        .iter()
        .find(|c| c.name() == "Work")
        .map(|c| c.id())
        .unwrap()
}

/// Makes a vault and adds notes: (title, reminders, in Work).
fn seed(dir: &Path, items: &[(&str, &[Option<CalendarDate>], bool)]) {
    make_vault(dir, PASSWORD);
    let mut session = Session::new(FsStore::new(vault_path(dir)), Box::new(SystemClock::new()));
    session
        .unlock(&MasterPassword::new(PASSWORD.to_owned()))
        .unwrap();
    let work = work_id(&session);
    for (title, expiries, in_work) in items {
        session
            .add_item(ItemInput {
                fields: expiries.iter().map(|e| field(*e)).collect(),
                title: Text::new((*title).to_owned()),
                category: in_work.then_some(work),
                favourite: false,
                data: ItemData::SecureNote {
                    body: SecretText::new("EXAMPLE body".to_owned()),
                },
            })
            .unwrap();
    }
}

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

/// Opens the app on the seeded vault and unlocks it through the form.
fn open(dir: &Path) -> Harness<'static, HolmApp> {
    let (app, clock) = test_app(dir);
    assert_eq!(from_unix_secs(clock.now_unix().0), Some(fake_today()));
    let mut harness = harness(app);
    harness.run();
    type_into(&mut harness, "Master password", PASSWORD);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(&mut harness, |a| a.screen_kind() == ScreenKind::Vault, WAIT);
    harness.run();
    harness
}

/// AccessKit nodes whose label is exactly `text`.
fn exact(harness: &Harness<'static, HolmApp>, text: &str) -> usize {
    harness.query_all_by_label(text).count()
}

/// AccessKit nodes whose label contains `text`.
fn containing(harness: &Harness<'static, HolmApp>, text: &str) -> usize {
    harness.query_all_by_label_contains(text).count()
}

/// Painted text shapes that contain `text`.
fn painted(harness: &Harness<'static, HolmApp>, text: &str) -> usize {
    harness
        .output()
        .shapes
        .iter()
        .filter(|c| matches!(&c.shape, Shape::Text(t) if t.galley.text().contains(text)))
        .count()
}

fn shown(harness: &Harness<'static, HolmApp>, title: &str) -> bool {
    exact(harness, title) == 1
}

fn click_chip(harness: &mut Harness<'static, HolmApp>, label: &str) {
    harness.get_by_role_and_label(Role::Button, label).click();
    harness.run();
}

#[test]
fn badge_expired() {
    let today = fake_today();
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path(), &[("Lapsed", &[Some(shift(today, -1))], false)]);
    let harness = open(dir.path());
    assert!(shown(&harness, "Lapsed"));
    assert_eq!(exact(&harness, "Expired"), 1);
}

#[test]
fn badge_in_n_days() {
    let today = fake_today();
    let dir = tempfile::tempdir().unwrap();
    seed(
        dir.path(),
        &[
            ("Five", &[Some(shift(today, 5))], false),
            ("One", &[Some(shift(today, 1))], false),
        ],
    );
    let harness = open(dir.path());
    assert_eq!(exact(&harness, "Expires in 5 days"), 1);
    assert_eq!(exact(&harness, "Expires in 1 day"), 1);
    assert_eq!(exact(&harness, "Expires in 1 days"), 0);
}

#[test]
fn badge_today() {
    let today = fake_today();
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path(), &[("Now", &[Some(today)], false)]);
    let harness = open(dir.path());
    assert_eq!(exact(&harness, "Expires today"), 1);
}

#[test]
fn badge_is_the_soonest() {
    let today = fake_today();
    let dir = tempfile::tempdir().unwrap();
    seed(
        dir.path(),
        &[(
            "Two",
            &[Some(shift(today, 9)), None, Some(shift(today, 2))],
            false,
        )],
    );
    let harness = open(dir.path());
    assert_eq!(exact(&harness, "Expires in 2 days"), 1);
    assert_eq!(exact(&harness, "Expires in 9 days"), 0);
}

#[test]
fn badge_omitted_when_no_expiry() {
    let dir = tempfile::tempdir().unwrap();
    seed(
        dir.path(),
        &[("Open field", &[None], false), ("No fields", &[], false)],
    );
    let harness = open(dir.path());
    assert!(shown(&harness, "Open field"));
    assert!(shown(&harness, "No fields"));
    assert_eq!(containing(&harness, "Expires"), 0);
    assert_eq!(exact(&harness, "Expired"), 0);
    assert_eq!(painted(&harness, "Expires"), 0);
}

#[test]
fn expiring_chip_filters() {
    let today = fake_today();
    let window = i64::from(EXPIRING_WITHIN_DAYS);
    let dir = tempfile::tempdir().unwrap();
    seed(
        dir.path(),
        &[
            ("Thirty", &[Some(shift(today, window))], false),
            ("Thirty-one", &[Some(shift(today, window + 1))], false),
            ("Lapsed", &[Some(shift(today, -1))], false),
            ("Without", &[None], false),
        ],
    );
    let mut harness = open(dir.path());
    for title in ["Thirty", "Thirty-one", "Lapsed", "Without"] {
        assert!(shown(&harness, title), "{title} before the chip");
    }
    click_chip(&mut harness, CHIP_EXPIRING);
    assert!(shown(&harness, "Thirty"));
    assert!(shown(&harness, "Lapsed"));
    assert!(!shown(&harness, "Thirty-one"));
    assert!(!shown(&harness, "Without"));
    click_chip(&mut harness, CHIP_EXPIRING);
    for title in ["Thirty", "Thirty-one", "Lapsed", "Without"] {
        assert!(shown(&harness, title), "{title} after the chip is off");
    }
}

#[test]
fn expiring_chip_combines_with_category() {
    let today = fake_today();
    let dir = tempfile::tempdir().unwrap();
    seed(
        dir.path(),
        &[
            ("Work due", &[Some(shift(today, 3))], true),
            ("Work later", &[Some(shift(today, 60))], true),
            ("Home due", &[Some(shift(today, 3))], false),
        ],
    );
    let mut harness = open(dir.path());
    click_chip(&mut harness, "Work");
    assert!(shown(&harness, "Work due"));
    assert!(shown(&harness, "Work later"));
    assert!(!shown(&harness, "Home due"));
    click_chip(&mut harness, CHIP_EXPIRING);
    assert!(shown(&harness, "Work due"));
    assert!(!shown(&harness, "Work later"));
    assert!(!shown(&harness, "Home due"));
}

#[test]
fn badge_has_no_secret() {
    let today = fake_today();
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path(), &[("Mail", &[Some(shift(today, 4))], false)]);
    let mut harness = open(dir.path());
    assert_eq!(exact(&harness, "Expires in 4 days"), 1);
    for text in [SECRET, LABEL] {
        assert_eq!(containing(&harness, text), 0, "{text} in AccessKit");
        assert_eq!(painted(&harness, text), 0, "{text} painted");
    }
    click_chip(&mut harness, CHIP_EXPIRING);
    assert!(shown(&harness, "Mail"));
    for text in [SECRET, LABEL] {
        assert_eq!(containing(&harness, text), 0, "{text} in AccessKit");
        assert_eq!(painted(&harness, text), 0, "{text} painted");
    }
}
