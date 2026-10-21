#![cfg(target_os = "macos")]
//! The create and unlock screens, driven headless through the whole app.

mod common;

use std::time::Duration;

use common::{OTHER_PASSWORD, PASSWORD, TestClock, harness, make_vault, run_until, test_app};
use eframe::egui::{Event, Key, accesskit::Role};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use holm_core::session::Session;
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::messages;
use holm_gui::worker::{Job, WorkDone};
use holm_platform::fs_store::FsStore;

const PASSWORD_LABEL: &str = "Master password";
const CONFIRM_LABEL: &str = "Confirm master password";
const UNDERSTOOD_LABEL: &str = "I understand Holm can't recover my vault";
const CREATE_BUTTON: &str = "Create vault";
const UNLOCK_BUTTON: &str = "Unlock";
const WAIT: Duration = Duration::from_secs(30);

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

fn is_disabled(harness: &Harness<'static, HolmApp>, label: &str) -> bool {
    harness.get_by_label(label).accesskit_node().is_disabled()
}

fn kind_is(kind: ScreenKind) -> impl Fn(&HolmApp) -> bool {
    move |app| app.screen_kind() == kind
}

fn tick_understood(harness: &mut Harness<'static, HolmApp>) {
    harness.get_by_label(UNDERSTOOD_LABEL).click();
    harness.run();
}

/// Types one unlock try and waits for its result. The try has started once the field
/// is empty again: the password moved out of the form to the worker. (A try that fails
/// before Argon2, such as on a symlink, can finish within the same step, so this does
/// not insist on seeing the `Working` screen.)
fn try_unlock(harness: &mut Harness<'static, HolmApp>, password: &str) {
    type_into(harness, PASSWORD_LABEL, password);
    assert!(!harness.state().secret_buffers_empty());
    harness.key_press(Key::Enter);
    harness.step();
    assert!(harness.state().secret_buffers_empty());
    run_until(
        harness,
        |app| app.screen_kind() != ScreenKind::Working,
        WAIT,
    );
}

#[test]
fn first_run_shows_create() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _clock) = test_app(dir.path());
    let mut harness = harness(app);
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Create);
    let _ = harness.get_by_label(PASSWORD_LABEL);
    let _ = harness.get_by_label(CONFIRM_LABEL);
    assert!(is_disabled(&harness, CREATE_BUTTON));
}

#[test]
fn create_needs_strong_match_and_checkbox() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _clock) = test_app(dir.path());
    let mut harness = harness(app);
    harness.run();

    // Weak, matching and ticked: still disabled.
    type_into(&mut harness, PASSWORD_LABEL, "password1234");
    type_into(&mut harness, CONFIRM_LABEL, "password1234");
    tick_understood(&mut harness);
    assert!(is_disabled(&harness, CREATE_BUTTON));
    assert_eq!(harness.state().screen_kind(), ScreenKind::Create);

    // Start over: a fresh app on a fresh folder.
    drop(harness);
    let dir = tempfile::tempdir().unwrap();
    let (app, _clock) = test_app(dir.path());
    let mut harness = common::harness(app);
    harness.run();

    // Strong but different: no error while typing, the button stays disabled, and
    // Enter (the confirm field still has focus) shows the mismatch.
    type_into(&mut harness, PASSWORD_LABEL, PASSWORD);
    type_into(&mut harness, CONFIRM_LABEL, OTHER_PASSWORD);
    assert!(harness.query_by_label(messages::PASSWORDS_DIFFER).is_none());
    assert!(is_disabled(&harness, CREATE_BUTTON));
    harness.key_press(Key::Enter);
    harness.run();
    let _ = harness.get_by_label(messages::PASSWORDS_DIFFER);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Create);

    // Strong and matching, but the box is not ticked: disabled. Editing a field
    // clears the mismatch line.
    for _ in 0..OTHER_PASSWORD.chars().count() {
        harness.key_press(Key::Backspace);
    }
    harness.run();
    harness.event(Event::Text(PASSWORD.to_owned()));
    harness.run();
    assert!(harness.query_by_label(messages::PASSWORDS_DIFFER).is_none());
    assert!(is_disabled(&harness, CREATE_BUTTON));

    // Ticked: enabled, and a click creates the vault on the worker.
    tick_understood(&mut harness);
    assert!(!is_disabled(&harness, CREATE_BUTTON));
    harness.get_by_label(CREATE_BUTTON).click();
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Working);
    run_until(&mut harness, kind_is(ScreenKind::Vault), WAIT);
    assert!(harness.state().is_unlocked());
    assert!(common::vault_path(dir.path()).is_file());
}

#[test]
fn fields_cleared_when_work_starts() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _clock) = test_app(dir.path());
    let mut harness = harness(app);
    harness.run();
    type_into(&mut harness, PASSWORD_LABEL, PASSWORD);
    type_into(&mut harness, CONFIRM_LABEL, PASSWORD);
    tick_understood(&mut harness);
    assert!(!harness.state().secret_buffers_empty());

    harness.get_by_label(CREATE_BUTTON).click();
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Working);
    // The form and its buffers are gone (wiped) while the worker runs: no password
    // field is on screen. (`secret_buffers_empty` is always true on Working, so it is
    // not asserted here; the unit test `submit_takes_both_fields` covers the wipe.)
    assert_eq!(harness.query_all_by_role(Role::PasswordInput).count(), 0);
    run_until(&mut harness, kind_is(ScreenKind::Vault), WAIT);
}

#[test]
fn existing_vault_shows_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let path = common::vault_path(dir.path());
    holm_platform::paths::ensure_vault_dir(&path).unwrap();
    std::fs::write(&path, b"not read by this test").unwrap();
    let (app, _clock) = test_app(dir.path());
    let mut harness = harness(app);
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    let _ = harness.get_by_label(PASSWORD_LABEL);
    assert!(harness.query_by_label(CONFIRM_LABEL).is_none());
    assert!(!harness.state().is_unlocked());
}

#[test]
fn wrong_password_shows_message() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let (app, _clock) = test_app(dir.path());
    let mut harness = harness(app);
    harness.run();
    try_unlock(&mut harness, OTHER_PASSWORD);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    harness.run();
    let _ = harness.get_by_label(messages::WRONG_PASSWORD);
    let _ = harness.get_by_label("1 failed try.");
    assert!(!harness.state().is_unlocked());
}

#[test]
fn throttle_wait_shown_and_button_disabled() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let (app, clock) = test_app(dir.path());
    let mut harness = harness(app);
    harness.run();
    for _ in 0..3 {
        try_unlock(&mut harness, OTHER_PASSWORD);
    }
    harness.run();
    let _ = harness.get_by_label("Too many tries. Try again in 2 s.");

    // The right password typed at once: the button is disabled and Enter starts nothing.
    type_into(&mut harness, PASSWORD_LABEL, PASSWORD);
    assert!(is_disabled(&harness, UNLOCK_BUTTON));
    harness.get_by_label(UNLOCK_BUTTON).click();
    harness.key_press(Key::Enter);
    for _ in 0..4 {
        harness.step();
        assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    }
    let _ = harness.get_by_label("Too many tries. Try again in 2 s.");

    // One second later the countdown moves without any input.
    clock.advance(Duration::from_secs(1));
    harness.step();
    let _ = harness.get_by_label("Too many tries. Try again in 1 s.");
    assert!(is_disabled(&harness, UNLOCK_BUTTON));

    // When the wait is over the button is enabled and the right password unlocks.
    clock.advance(Duration::from_secs(1));
    harness.step();
    assert!(harness.query_by_label_contains("Try again in").is_none());
    assert!(!is_disabled(&harness, UNLOCK_BUTTON));
    harness.get_by_label(UNLOCK_BUTTON).click();
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Working);
    run_until(&mut harness, kind_is(ScreenKind::Vault), WAIT);
    assert!(harness.state().is_unlocked());
}

#[test]
fn throttle_countdown_asks_for_a_frame_at_the_next_second() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let (app, clock) = test_app(dir.path());
    let mut harness = harness(app);
    harness.run();
    for _ in 0..3 {
        try_unlock(&mut harness, OTHER_PASSWORD);
    }
    harness.run();
    // Half a second into the 2 s wait, 1.5 s remain: the next label change is in 0.5 s.
    clock.advance(Duration::from_millis(500));
    let ctx = eframe::egui::Context::default();
    let delay = std::sync::Arc::new(std::sync::Mutex::new(None::<Duration>));
    let seen = delay.clone();
    ctx.set_request_repaint_callback(move |info| {
        let mut slot = seen.lock().unwrap();
        // Keep the shortest delay asked for.
        if slot.is_none_or(|d| info.delay < d) {
            *slot = Some(info.delay);
        }
    });
    harness
        .state_mut()
        .tick(&ctx, &common::FakeWindow::default());
    let asked = delay.lock().unwrap().expect("tick asked for no frame");
    assert!(
        !asked.is_zero() && asked <= Duration::from_millis(500),
        "countdown frame asked in {asked:?}"
    );
}

/// A spawner whose worker is gone at once: it drops the session and the sender, as a
/// panicked worker thread would.
fn lost_worker(
    session: Session<FsStore>,
    job: Job,
    _wake: Box<dyn Fn() + Send>,
) -> std::sync::mpsc::Receiver<WorkDone> {
    drop((session, job));
    std::sync::mpsc::channel().1
}

/// A spawner whose create writes the vault and then reports a store error, as a failed
/// folder sync after the file was written does.
fn create_then_sync_fails(
    mut session: Session<FsStore>,
    job: Job,
    _wake: Box<dyn Fn() + Send>,
) -> std::sync::mpsc::Receiver<WorkDone> {
    let Job::Create(password, kdf) = job else {
        panic!("expected a create job");
    };
    session.create(&password, &kdf).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(WorkDone {
        session,
        kind: holm_gui::worker::JobKind::Create,
        result: Err(holm_core::error::CoreError::Store(
            holm_core::store::StoreError::Io(std::io::ErrorKind::Other),
        )),
        added: None,
        returned: None,
        transfer: None,
        phrase: None,
    })
    .unwrap();
    rx
}

#[test]
fn create_failing_after_write_offers_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _clock) = test_app(dir.path());
    let mut harness = harness(app.with_spawner(create_then_sync_fails));
    harness.run();
    type_into(&mut harness, PASSWORD_LABEL, PASSWORD);
    type_into(&mut harness, CONFIRM_LABEL, PASSWORD);
    harness.get_by_label(UNDERSTOOD_LABEL).click();
    harness.run();
    harness.get_by_label(CREATE_BUTTON).click();
    run_until(&mut harness, kind_is(ScreenKind::Unlock), WAIT);
    harness.run();
    let _ = harness.get_by_label(messages::CREATE_MAYBE_SAVED);
}

#[test]
fn worker_panic_is_fatal_not_hang() {
    let dir = tempfile::tempdir().unwrap();
    let path = common::vault_path(dir.path());
    holm_platform::paths::ensure_vault_dir(&path).unwrap();
    std::fs::write(&path, b"EXAMPLE vault bytes").unwrap();
    let (app, _clock) = test_app(dir.path());
    let mut harness = harness(app.with_spawner(lost_worker));
    harness.run();
    type_into(&mut harness, PASSWORD_LABEL, PASSWORD);
    harness.key_press(Key::Enter);
    run_until(&mut harness, kind_is(ScreenKind::Fatal), WAIT);
    harness.run();
    let _ = harness.get_by_label(messages::WORKER_LOST);
    assert_eq!(std::fs::read(&path).unwrap(), b"EXAMPLE vault bytes");
}

#[test]
fn second_instance_shows_fixed_text_and_no_vault() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let (first, _clock) = test_app(dir.path());
    assert_eq!(first.screen_kind(), ScreenKind::Unlock);

    let (second, _clock) = test_app(dir.path());
    assert_eq!(second.screen_kind(), ScreenKind::Fatal);
    let mut harness = harness(second);
    harness.run();
    let _ = harness.get_by_label(messages::ALREADY_OPEN);
    assert_eq!(harness.query_all_by_role(Role::PasswordInput).count(), 0);
    assert!(harness.query_by_label(PASSWORD_LABEL).is_none());
    assert!(!harness.state().is_unlocked());
    drop(first);
}

#[test]
fn lock_released_when_app_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let (first, _clock) = test_app(dir.path());
    assert_eq!(first.screen_kind(), ScreenKind::Create);
    drop(first);
    let (again, _clock) = test_app(dir.path());
    assert_eq!(again.screen_kind(), ScreenKind::Create);
}

#[test]
fn permission_denied_text() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let holm_dir = dir.path().join("Holm");
    std::fs::create_dir(&holm_dir).unwrap();
    std::fs::set_permissions(&holm_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let (app, _clock) = test_app(dir.path());
    assert_eq!(app.screen_kind(), ScreenKind::Fatal);
    let mut harness = harness(app);
    harness.run();
    let _ = harness.get_by_label(messages::DIR_PERMISSIONS);
    assert_eq!(harness.query_all_by_role(Role::PasswordInput).count(), 0);
}

#[test]
fn symlink_at_vault_path_shows_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let path = common::vault_path(dir.path());
    holm_platform::paths::ensure_vault_dir(&path).unwrap();
    let target = dir.path().join("elsewhere.vault");
    std::fs::write(&target, b"EXAMPLE").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();

    let (app, _clock) = test_app(dir.path());
    let mut harness = harness(app);
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    try_unlock(&mut harness, PASSWORD);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    harness.run();
    let _ = harness.get_by_label(messages::NOT_A_VAULT);
    assert!(path.is_symlink());
    assert_eq!(std::fs::read(&target).unwrap(), b"EXAMPLE");
}

#[test]
fn vault_exists_switches_to_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _clock) = test_app(dir.path());
    let mut harness = harness(app);
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Create);

    // Another process makes the vault after this app started on Create.
    let path = common::vault_path(dir.path());
    std::fs::write(&path, b"EXAMPLE other vault").unwrap();

    type_into(&mut harness, PASSWORD_LABEL, PASSWORD);
    type_into(&mut harness, CONFIRM_LABEL, PASSWORD);
    tick_understood(&mut harness);
    harness.get_by_label(CREATE_BUTTON).click();
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Working);
    run_until(
        &mut harness,
        |app| app.screen_kind() != ScreenKind::Working,
        WAIT,
    );
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert!(!harness.state().is_unlocked());
    assert_eq!(std::fs::read(&path).unwrap(), b"EXAMPLE other vault");
}

#[test]
fn test_clock_is_shared() {
    let clock = TestClock::new();
    let copy = clock.clone();
    clock.advance(Duration::from_secs(2));
    assert_eq!(
        holm_core::clock::Clock::monotonic(&copy),
        Duration::from_secs(2)
    );
}
