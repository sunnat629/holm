#![cfg(target_os = "macos")]
//! Copy and paste through Holm's own clipboard, driven headless with a fake clipboard.
//!
//! The kittest harness never calls `eframe::App::raw_input_hook`, so the tests that
//! need it build the frame's `RawInput` themselves, run the hook on it, and hand it to
//! the harness for the next step, as eframe does before every frame.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{FakeClipboard, PASSWORD, harness, make_vault, run_until, test_app_with_clipboard};
use eframe::App as _;
use eframe::egui::{Event, Key, Modifiers, OutputCommand};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::messages;
use holm_gui::secret_input::MASTER_CAP;

const WAIT: Duration = Duration::from_secs(30);
const PASTED: &str = "EXAMPLE-pasted";
const SECRET: &str = "EXAMPLE-zq9-pass";
const TITLE: &str = "Title";

/// An app on a fresh vault in `dir`, on the unlock screen, using `fake`.
fn unlock_screen(dir: &Path, fake: &FakeClipboard) -> Harness<'static, HolmApp> {
    make_vault(dir, PASSWORD);
    let (app, _clock) = test_app_with_clipboard(dir, Box::new(fake.clone()));
    let mut harness = harness(app);
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    harness
}

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

/// An app on a fresh vault in `dir`, unlocked, using `fake`.
fn unlocked(dir: &Path, fake: &FakeClipboard) -> Harness<'static, HolmApp> {
    let mut harness = unlock_screen(dir, fake);
    type_into(&mut harness, "Master password", PASSWORD);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(&mut harness, |a| a.screen_kind() == ScreenKind::Vault, WAIT);
    harness.run();
    harness
}

/// Adds one login and leaves it selected in the read-only view.
fn add_login(harness: &mut Harness<'static, HolmApp>) {
    harness.get_by_label("New login").click();
    harness.run();
    type_into(harness, TITLE, "Example Mail");
    type_into(harness, "Password", SECRET);
    harness.get_by_label("Save").click();
    harness.step();
    run_until(harness, |a| a.screen_kind() == ScreenKind::Vault, WAIT);
    harness.run();
}

fn cmd(key: Key, pressed: bool) -> Event {
    Event::Key {
        key,
        physical_key: None,
        pressed,
        repeat: false,
        modifiers: Modifiers::COMMAND,
    }
}

/// Runs the next frame the way eframe does: a Cmd+`key` press and release go into the
/// raw input, `raw_input_hook` sees it, then the frame runs. Returns the texts of the
/// `Event::Paste` events the hook left in the input.
fn press_through_hook(
    harness: &mut Harness<'static, HolmApp>,
    key: Key,
    extra: &[Event],
) -> Vec<String> {
    let mut raw = std::mem::take(harness.input_mut());
    raw.events.push(cmd(key, true));
    raw.events.extend_from_slice(extra);
    raw.events.push(cmd(key, false));
    let ctx = harness.ctx.clone();
    harness.state_mut().raw_input_hook(&ctx, &mut raw);
    let pastes = raw
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Paste(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    *harness.input_mut() = raw;
    harness.step();
    pastes
}

/// Whether the last frame asked the platform to copy anything.
fn copied_text(harness: &Harness<'static, HolmApp>) -> bool {
    harness
        .output()
        .platform_output
        .commands
        .iter()
        .any(|c| matches!(c, OutputCommand::CopyText(_)))
}

#[test]
fn copy_uses_secret_clipboard_only() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeClipboard::default();
    let mut harness = unlocked(dir.path(), &fake);
    add_login(&mut harness);
    assert!(fake.0.borrow().sets.is_empty());

    harness.get_by_label("Copy").click();
    for _ in 0..4 {
        harness.step();
        assert!(!copied_text(&harness), "egui's copy_text was used");
    }
    harness.run();
    assert!(!copied_text(&harness));

    let state = fake.0.borrow();
    assert_eq!(state.sets.len(), 1, "one set_secret call");
    assert_eq!(state.sets[0].as_str(), SECRET);
    drop(state);
    let _ = harness.get_by_label(messages::COPIED);
    assert!(harness.query_by_label(messages::COPY_FAILED).is_none());
}

#[test]
fn copy_failure_shows_message() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeClipboard::default();
    fake.0.borrow_mut().fail = true;
    let mut harness = unlocked(dir.path(), &fake);
    add_login(&mut harness);

    harness.get_by_label("Copy").click();
    harness.run();
    assert_eq!(fake.0.borrow().sets.len(), 1);
    let _ = harness.get_by_label(messages::COPY_FAILED);
    assert!(harness.query_by_label(messages::COPIED).is_none());
    assert!(!copied_text(&harness));
}

#[test]
fn cmd_v_pastes_into_secret_field() {
    let dir = tempfile::tempdir().unwrap();
    // The trailing newline is a control character and is skipped.
    let fake = FakeClipboard::serving(&format!("{PASTED}\n"));
    let mut harness = unlock_screen(dir.path(), &fake);
    harness.get_by_label("Master password").click();
    harness.run();

    let pastes = press_through_hook(&mut harness, Key::V, &[]);
    assert!(
        pastes.is_empty(),
        "no Event::Paste reaches egui for a secret"
    );
    harness.run();

    assert_eq!(harness.state().secret_char_count(), 14);
    assert_eq!(fake.0.borrow().gets, 1);
    // The pasted password unlocks nothing yet; it is only in the field.
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
}

#[test]
fn cmd_v_over_cap_is_refused_with_message() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeClipboard::serving(&"x".repeat(MASTER_CAP + 1));
    let mut harness = unlock_screen(dir.path(), &fake);
    harness.get_by_label("Master password").click();
    harness.run();
    harness.event(Event::Text("ab".to_owned()));
    harness.run();

    let pastes = press_through_hook(&mut harness, Key::V, &[]);
    assert!(pastes.is_empty());
    harness.run();

    // Nothing was cut and pasted: the field keeps what was typed, and says why.
    assert_eq!(harness.state().secret_char_count(), 2);
    let _ = harness.get_by_label(messages::PASTE_TOO_LONG);
}

#[test]
fn cmd_v_with_nothing_focused_reads_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeClipboard::serving(PASTED);
    let mut harness = unlock_screen(dir.path(), &fake);

    let pastes = press_through_hook(&mut harness, Key::V, &[]);
    harness.run();
    assert!(pastes.is_empty());
    assert_eq!(fake.0.borrow().gets, 0, "the clipboard was not read");
    assert!(harness.state().secret_buffers_empty());
}

#[test]
fn cmd_v_pastes_into_title() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeClipboard::serving(PASTED);
    let mut harness = unlocked(dir.path(), &fake);
    harness.get_by_label("New login").click();
    harness.run();
    harness.get_by_label(TITLE).click();
    harness.run();

    let pastes = press_through_hook(&mut harness, Key::V, &[]);
    assert_eq!(pastes, vec![PASTED.to_owned()], "one Event::Paste");
    harness.run();

    assert_eq!(harness.get_by_label(TITLE).value().as_deref(), Some(PASTED));
    assert_eq!(fake.0.borrow().gets, 1);
    assert!(!harness.state().secret_buffers_empty());
}

#[test]
fn cmd_c_in_title_copies_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeClipboard::default();
    let mut harness = unlocked(dir.path(), &fake);
    harness.get_by_label("New login").click();
    harness.run();
    type_into(&mut harness, TITLE, "Example Mail");

    // Select all, then Cmd+C and Cmd+X, each with the copy or cut event a platform
    // could add: the hook drops those events, so the field copies nothing.
    harness.key_press_modifiers(Modifiers::COMMAND, Key::A);
    harness.run();
    let pastes = press_through_hook(&mut harness, Key::C, &[Event::Copy]);
    assert!(pastes.is_empty());
    assert!(!copied_text(&harness));
    let _ = press_through_hook(&mut harness, Key::X, &[Event::Cut]);
    assert!(!copied_text(&harness));
    harness.run();
    assert!(!copied_text(&harness));

    assert!(fake.0.borrow().sets.is_empty(), "no set_secret");
    assert_eq!(
        harness.get_by_label(TITLE).value().as_deref(),
        Some("Example Mail"),
        "the cut did not happen"
    );
}

/// Sets a fake value on the real pasteboard and checks that it carries
/// `org.nspasteboard.ConcealedType`. It replaces whatever is on the clipboard, so it is
/// run once by hand (Task 7): `cargo test -p holm-gui --locked --test clipboard --
/// --ignored system_clipboard_marks_concealed`.
#[test]
#[ignore = "uses the real pasteboard; run by hand"]
fn system_clipboard_marks_concealed() {
    use holm_gui::clipboard::{SecretClipboard as _, SystemClipboard};

    let mut clipboard = SystemClipboard::new();
    clipboard
        .set_secret("EXAMPLE-concealed")
        .expect("the pasteboard takes the text");
    let out = std::process::Command::new("osascript")
        .args([
            "-l",
            "JavaScript",
            "-e",
            "ObjC.import('AppKit'); \
             ObjC.deepUnwrap($.NSPasteboard.generalPasteboard.types).join('\\n')",
        ])
        .output()
        .expect("osascript runs");
    let types = String::from_utf8(out.stdout).expect("UTF-8 type names");
    assert!(
        types.lines().any(|t| t == "org.nspasteboard.ConcealedType"),
        "types: {types}"
    );
    assert_eq!(
        clipboard.get_text().as_deref().map(String::as_str),
        Some("EXAMPLE-concealed")
    );
}
