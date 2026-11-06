#![cfg(target_os = "macos")]
//! The login form in the default window size: with many custom fields the form is
//! taller than the window, and its Save and Cancel buttons must still be reachable by
//! scrolling. Also the preset list. Driven headless on a fresh vault; the window size
//! is deliberately left at the harness default.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{PASSWORD, harness, make_vault, run_until, test_app};
use eframe::egui::{Event, Key, accesskit::Role};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::messages;

const WAIT: Duration = Duration::from_secs(30);

const PRESET: &str = "Preset";
const FIELD_NAME: &str = "Field name";

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

/// An empty vault in `dir`, unlocked, in the default window, with the new-login form
/// open.
fn open_new_login(dir: &Path) -> Harness<'static, HolmApp> {
    make_vault(dir, PASSWORD);
    let (app, _clock) = test_app(dir);
    let mut harness = harness(app);
    harness.run();
    unlock(&mut harness);
    common::new_login(&mut harness);
    harness.run();
    harness
}

/// Opens the preset picker.
fn open_presets(harness: &mut Harness<'static, HolmApp>) {
    harness
        .query_all_by_label(PRESET)
        .rfind(|n| n.accesskit_node().role() == Role::ComboBox)
        .expect("the preset picker")
        .click();
    harness.run();
}

#[test]
fn save_is_reachable_with_ten_fields() {
    let dir = tempfile::tempdir().unwrap();
    let mut harness = open_new_login(dir.path());

    open_presets(&mut harness);
    click(&mut harness, "Cloudflare");
    for _ in 0..6 {
        click(&mut harness, messages::ADD_FIELD);
    }
    assert_eq!(
        count(&harness, FIELD_NAME),
        10,
        "four preset rows and six new"
    );

    harness.get_by_label("Save").scroll_to_me();
    harness.run();
    let window_height = f64::from(harness.ctx.content_rect().height());
    let bounds = harness
        .get_by_label("Save")
        .accesskit_node()
        .bounding_box()
        .expect("Save has a position");
    assert!(bounds.y0 >= 0.0, "Save starts below the top: {bounds:?}");
    assert!(
        bounds.y1 <= window_height,
        "Save ends inside the window ({window_height}): {bounds:?}"
    );

    click(&mut harness, "Cancel");
    assert!(harness.query_by_label("Save").is_none(), "the form closed");
}

#[test]
fn preset_list_has_bank_card_and_custom() {
    let dir = tempfile::tempdir().unwrap();
    let mut harness = open_new_login(dir.path());

    open_presets(&mut harness);
    assert_eq!(count(&harness, "Bank card"), 1);
    assert_eq!(count(&harness, "Custom (empty)"), 1);

    click(&mut harness, "Custom (empty)");
    assert_eq!(count(&harness, FIELD_NAME), 0, "an empty draft has no rows");
}

/// Whether `text` is a card's updated time: "HH:MM", "D Mon" or "D Mon YYYY".
fn is_updated_time(text: &str) -> bool {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let b = text.as_bytes();
    let clock = b.len() == 5 && b[2] == b':' && [0, 1, 3, 4].iter().all(|&i| b[i].is_ascii_digit());
    let parts: Vec<&str> = text.split(' ').collect();
    let date = (2..=3).contains(&parts.len())
        && parts[0].parse::<u8>().is_ok_and(|d| (1..=31).contains(&d))
        && MONTHS.contains(&parts[1])
        && parts
            .get(2)
            .is_none_or(|y| y.len() == 4 && y.parse::<u16>().is_ok());
    clock || date
}

#[test]
fn saved_login_shows_as_a_card_with_its_updated_time() {
    let dir = tempfile::tempdir().unwrap();
    let mut harness = open_new_login(dir.path());
    type_into(&mut harness, "Title", "Example Card");
    click(&mut harness, "Save");
    run_until(
        &mut harness,
        |app| app.screen_kind() == ScreenKind::Vault,
        WAIT,
    );
    harness.run();

    // The list card's title is the leftmost of the two (the detail heading is the other).
    let title_left = harness
        .query_all_by_label("Example Card")
        .filter_map(|n| n.accesskit_node().bounding_box().map(|b| b.x0))
        .fold(f64::INFINITY, f64::min);
    let times: Vec<String> = harness
        .root()
        .children_recursive()
        // A plain label publishes its text as the node's value.
        .filter(|n| n.accesskit_node().role() == Role::Label)
        .filter_map(|n| n.accesskit_node().value().map(|l| l.to_string()))
        .filter(|l| is_updated_time(l))
        .collect();
    assert_eq!(times.len(), 1, "one card, one updated time: {times:?}");
    let time_left = harness
        .root()
        .children_recursive()
        .find(|n| n.accesskit_node().value().as_deref() == Some(times[0].as_str()))
        .and_then(|n| n.accesskit_node().bounding_box())
        .expect("the time has bounds")
        .x0;
    assert!(time_left > title_left, "the time sits right of the title");
    assert_eq!(
        count(&harness, "Example Card"),
        2,
        "card title and detail heading"
    );
}
