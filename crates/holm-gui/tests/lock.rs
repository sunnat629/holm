#![cfg(target_os = "macos")]
//! Manual, idle and minimise lock, driven headless through the whole app.
//!
//! The harness runs `tick` then `show` each frame, as eframe runs `logic` then `ui`.
//! The session and the UI share one `TestClock`, so a test moves time by hand.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use common::{
    FakeWindow, PASSWORD, TestClock, harness, harness_with_window, make_vault,
    make_vault_with_auto_lock, run_until, test_app, vault_path,
};
use eframe::egui::{Event, Key, Modifiers, ViewportId, pos2};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use holm_core::session::Session;
use holm_gui::app::{HolmApp, LockNote, LockReason, ScreenKind};
use holm_gui::messages;
use holm_gui::worker::{self, Job, WorkDone};
use holm_platform::fs_store::FsStore;

const WAIT: Duration = Duration::from_secs(30);
const SECRET: &str = "EXAMPLE-zq9-pass";
const ROW_TITLE: &str = "Example Mail";
const DOTS: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

fn vault_screen(app: &HolmApp) -> bool {
    app.screen_kind() == ScreenKind::Vault
}

/// Types the master password on the unlock screen and waits for the vault.
fn unlock(harness: &mut Harness<'static, HolmApp>) {
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    type_into(harness, "Master password", PASSWORD);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(harness, vault_screen, WAIT);
    harness.run();
}

/// An app on the vault already in `dir`, unlocked and showing the list.
fn reopen(dir: &Path) -> (Harness<'static, HolmApp>, TestClock) {
    let (app, clock) = test_app(dir);
    let mut harness = harness(app);
    harness.run();
    unlock(&mut harness);
    (harness, clock)
}

/// A fresh vault in `dir` with default settings, open.
fn open(dir: &Path) -> (Harness<'static, HolmApp>, TestClock) {
    make_vault(dir, PASSWORD);
    reopen(dir)
}

/// [`open`] with a window the test can minimise.
fn open_in_window(dir: &Path) -> (Harness<'static, HolmApp>, TestClock, FakeWindow) {
    make_vault(dir, PASSWORD);
    let (app, clock) = test_app(dir);
    let window = FakeWindow::default();
    let mut harness = harness_with_window(app, window.clone());
    harness.run();
    unlock(&mut harness);
    (harness, clock, window)
}

/// The open vault's auto-lock time, from its settings.
fn auto_lock(harness: &Harness<'static, HolmApp>) -> Duration {
    harness.state().auto_lock_time()
}

fn line(reason: LockReason, discarded_unsaved: bool, auto_lock: Duration) -> String {
    messages::lock_line(
        &LockNote {
            reason,
            discarded_unsaved,
        },
        auto_lock,
    )
}

fn assert_locked(harness: &Harness<'static, HolmApp>, expected_line: &str) {
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert!(!harness.state().is_unlocked());
    assert!(harness.state().secret_buffers_empty());
    let _ = harness.get_by_label(expected_line);
}

/// Adds one login and leaves it selected in the read-only view.
fn add_example(harness: &mut Harness<'static, HolmApp>) {
    harness.get_by_label("New login").click();
    harness.run();
    type_into(harness, "Title", ROW_TITLE);
    type_into(harness, "Username", "ada@example.com");
    type_into(harness, "Password", SECRET);
    harness.get_by_label("Save").click();
    harness.step();
    run_until(harness, vault_screen, WAIT);
    harness.run();
}

/// Opens a vault and leaves the session dirty: the vault folder is opened to other
/// users, so the add stays in memory and its save fails. Returns the folder, to fix
/// its mode again.
fn open_dirty(dir: &Path) -> (Harness<'static, HolmApp>, TestClock, std::path::PathBuf) {
    let (harness, clock, folder, _window) = open_dirty_in_window(dir);
    (harness, clock, folder)
}

/// [`open_dirty`] with a window the test can minimise.
fn open_dirty_in_window(
    dir: &Path,
) -> (
    Harness<'static, HolmApp>,
    TestClock,
    std::path::PathBuf,
    FakeWindow,
) {
    let (mut harness, clock, window) = open_in_window(dir);
    let folder = vault_path(dir).parent().unwrap().to_owned();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o777)).unwrap();
    add_example(&mut harness);
    let _ = harness.get_by_label(messages::DIR_PERMISSIONS);
    (harness, clock, folder, window)
}

fn private(folder: &Path) {
    std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// How many accessibility nodes carry `needle` in a label, value or description.
fn nodes_with(harness: &Harness<'static, HolmApp>, needle: &str) -> usize {
    harness
        .root()
        .children_recursive()
        .filter(|node| {
            let access = node.accesskit_node();
            [access.label(), access.value(), access.description()]
                .iter()
                .flatten()
                .any(|t| t.contains(needle))
        })
        .count()
}

fn set_viewport(
    harness: &mut Harness<'static, HolmApp>,
    f: impl FnOnce(&mut eframe::egui::ViewportInfo),
) {
    f(harness
        .input_mut()
        .viewports
        .get_mut(&ViewportId::ROOT)
        .unwrap());
}

fn pointer_move(harness: &mut Harness<'static, HolmApp>) {
    harness.event(Event::PointerMoved(pos2(450.0, 320.0)));
    harness.run();
}

#[test]
fn lock_button_returns_to_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    harness.get_by_label("Lock").click();
    harness.run();
    assert_locked(&harness, "Locked.");
    assert_eq!(
        harness.state().lock_note(),
        Some(LockNote {
            reason: LockReason::Manual,
            discarded_unsaved: false
        })
    );
}

#[test]
fn cmd_l_locks() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    harness.key_press_modifiers(Modifiers::COMMAND, Key::L);
    harness.run();
    assert_locked(&harness, "Locked.");
}

#[test]
fn idle_locks_after_auto_lock_time() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock) = open(dir.path());
    let a = auto_lock(&harness);
    clock.advance(a - Duration::from_secs(1));
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    assert!(harness.state().is_unlocked());
    clock.advance(Duration::from_secs(1));
    harness.run();
    assert_locked(&harness, &line(LockReason::Idle, false, a));
}

#[test]
fn idle_lock_runs_without_ui() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock) = open(dir.path());
    let a = auto_lock(&harness);
    clock.advance(a);
    // Only `tick`, as eframe's `logic` while the window is hidden; `show` never runs.
    let ctx = harness.ctx.clone();
    harness.state_mut().tick(&ctx, &FakeWindow::default());
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert!(!harness.state().is_unlocked());
    assert_eq!(
        harness.state().lock_note().map(|n| n.reason),
        Some(LockReason::Idle)
    );
}

#[test]
fn activity_resets_idle() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock) = open(dir.path());
    let a = auto_lock(&harness);
    clock.advance(a * 2 / 3);
    harness.run();
    pointer_move(&mut harness);
    clock.advance(a * 2 / 3);
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    assert!(harness.state().is_unlocked());
    // A full auto-lock time after the move, it locks.
    clock.advance(a / 3);
    harness.run();
    assert_locked(&harness, &line(LockReason::Idle, false, a));
}

#[test]
fn stale_input_in_tick_does_not_reset() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock) = open(dir.path());
    let a = auto_lock(&harness);
    clock.advance(a * 2 / 3);
    harness.run();
    // The window is hidden (covered); a frame still runs with input in it.
    set_viewport(&mut harness, |v| v.occluded = Some(true));
    harness.event(Event::PointerMoved(pos2(450.0, 320.0)));
    harness.key_press(Key::A);
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    // No activity was noted: the lock fires at the original time.
    clock.advance(a - a * 2 / 3);
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert!(!harness.state().is_unlocked());
    assert_eq!(
        harness.state().lock_note().map(|n| n.reason),
        Some(LockReason::Idle)
    );
}

#[test]
fn minimise_locks_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, window) = open_in_window(dir.path());
    // As AppKit reports it; eframe's own `minimized` field stays `Some(false)` on macOS.
    window.set_minimised(true);
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert!(!harness.state().is_unlocked());
    window.set_minimised(false);
    harness.run();
    assert_locked(&harness, "Locked when the window was minimised.");
}

#[test]
fn lock_wipes_an_open_form() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    harness.get_by_label("New login").click();
    harness.run();
    type_into(&mut harness, "Title", ROW_TITLE);
    type_into(&mut harness, "Password", SECRET);
    assert!(!harness.state().secret_buffers_empty());
    harness.key_press_modifiers(Modifiers::COMMAND, Key::L);
    harness.run();
    assert_locked(&harness, "Locked.");
    assert_eq!(harness.state().secret_char_count(), 0);
    assert_eq!(nodes_with(&harness, ROW_TITLE), 0);
}

#[test]
fn reveal_hidden_by_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    add_example(&mut harness);
    harness.get_by_label("Reveal").click();
    harness.run();
    assert_eq!(nodes_with(&harness, SECRET), 1);
    harness.get_by_label("Lock").click();
    harness.run();
    assert_eq!(nodes_with(&harness, SECRET), 0);
    unlock(&mut harness);
    harness.get_by_label(ROW_TITLE).click();
    harness.run();
    let _ = harness.get_by_label(DOTS);
    let _ = harness.get_by_label("Reveal");
    assert_eq!(nodes_with(&harness, SECRET), 0);
}

#[test]
fn unlock_after_lock_sees_item() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    add_example(&mut harness);
    harness.key_press_modifiers(Modifiers::COMMAND, Key::L);
    harness.run();
    assert_locked(&harness, "Locked.");
    unlock(&mut harness);
    assert!(harness.query_by_label("Locked.").is_none());
    harness.get_by_label(ROW_TITLE).click();
    harness.run();
    let _ = harness.get_by_label("Username: ada@example.com");
}

#[test]
fn manual_lock_with_unsaved_asks() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, folder) = open_dirty(dir.path());
    harness.get_by_label("Lock").click();
    harness.run();
    let _ = harness.get_by_label(messages::UNSAVED_ON_LOCK);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    assert!(harness.state().is_unlocked());
    // Cmd+L asks the same way.
    harness.get_by_label("Cancel").click();
    harness.run();
    assert!(harness.query_by_label(messages::UNSAVED_ON_LOCK).is_none());
    harness.key_press_modifiers(Modifiers::COMMAND, Key::L);
    harness.run();
    let _ = harness.get_by_label(messages::UNSAVED_ON_LOCK);
    assert!(harness.state().is_unlocked());
    private(&folder);
}

#[test]
fn lock_anyway_discards() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, folder) = open_dirty(dir.path());
    let a = auto_lock(&harness);

    // Cancel keeps the vault open, and the change in memory.
    harness.get_by_label("Lock").click();
    harness.run();
    harness.get_by_label("Cancel").click();
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    assert!(harness.state().is_unlocked());
    assert!(harness.query_by_label(ROW_TITLE).is_some());

    harness.get_by_label("Lock").click();
    harness.run();
    harness.get_by_label("Lock anyway").click();
    harness.run();
    let expected = line(LockReason::Manual, true, a);
    assert!(expected.ends_with("Unsaved changes were discarded."));
    assert_locked(&harness, &expected);

    // The change was never written.
    private(&folder);
    unlock(&mut harness);
    assert!(harness.query_by_label(ROW_TITLE).is_none());
}

#[test]
fn save_and_lock_saves_then_locks() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, folder) = open_dirty(dir.path());
    private(&folder);
    harness.get_by_label("Lock").click();
    harness.run();
    harness.get_by_label("Save and lock").click();
    harness.run();
    assert_locked(&harness, "Locked.");
    unlock(&mut harness);
    assert!(harness.query_by_label(ROW_TITLE).is_some());
}

#[test]
fn save_and_lock_failure_keeps_vault_open() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, folder) = open_dirty(dir.path());
    harness.get_by_label("Lock").click();
    harness.run();
    harness.get_by_label("Save and lock").click();
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    assert!(harness.state().is_unlocked());
    assert!(harness.query_by_label(messages::UNSAVED_ON_LOCK).is_none());
    let _ = harness.get_by_label(messages::DIR_PERMISSIONS);
    let _ = harness.get_by_label("Try again");
    private(&folder);
}

#[test]
fn idle_lock_never_waits() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock, folder) = open_dirty(dir.path());
    let a = auto_lock(&harness);
    clock.advance(a);
    harness.run();
    assert!(harness.query_by_label(messages::UNSAVED_ON_LOCK).is_none());
    assert_locked(&harness, &line(LockReason::Idle, true, a));
    private(&folder);
}

#[test]
fn minimise_lock_never_waits() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, folder, window) = open_dirty_in_window(dir.path());
    harness.get_by_label("Lock").click();
    harness.run();
    let _ = harness.get_by_label(messages::UNSAVED_ON_LOCK);
    // The dialog is open; minimising still locks at once.
    window.set_minimised(true);
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert_eq!(
        harness.state().lock_note(),
        Some(LockNote {
            reason: LockReason::Minimised,
            discarded_unsaved: true
        })
    );
    private(&folder);
}

#[test]
fn warning_30s_before_idle() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock) = open(dir.path());
    let a = auto_lock(&harness);
    clock.advance(a - Duration::from_secs(31));
    harness.run();
    assert_eq!(nodes_with(&harness, "because of no activity"), 0);
    clock.advance(Duration::from_secs(1));
    harness.run();
    let _ = harness.get_by_label(&messages::idle_warning(Duration::from_secs(30)));
    let _ = harness.get_by_label("Locking in 30 s because of no activity.");
    clock.advance(Duration::from_secs(1));
    harness.run();
    let _ = harness.get_by_label("Locking in 29 s because of no activity.");
    // Any activity clears it.
    pointer_move(&mut harness);
    assert_eq!(nodes_with(&harness, "because of no activity"), 0);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
}

#[test]
fn idle_text_follows_settings() {
    let dir = tempfile::tempdir().unwrap();
    make_vault_with_auto_lock(dir.path(), PASSWORD, 600);
    let (mut harness, clock) = reopen(dir.path());
    let a = auto_lock(&harness);
    assert_eq!(a, Duration::from_secs(600));
    clock.advance(Duration::from_secs(300));
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    clock.advance(Duration::from_secs(300));
    harness.run();
    assert_locked(&harness, "Locked after 10 minutes without use.");
    assert_eq!(nodes_with(&harness, "5 minutes"), 0);
}

/// Held by `idle_during_job_locks_on_finish` while its worker must wait. Only that test
/// uses [`held_worker`], so other tests never wait on it.
static HOLD_WORKER: Mutex<()> = Mutex::new(());

/// A spawner whose worker waits until [`HOLD_WORKER`] is free, then runs the job on
/// the real worker and passes its answer on.
fn held_worker(
    session: Session<FsStore>,
    job: Job,
    wake: Box<dyn Fn() + Send>,
) -> Receiver<WorkDone> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        drop(HOLD_WORKER.lock().unwrap_or_else(PoisonError::into_inner));
        let done = worker::spawn(session, job, || {}).recv();
        if let Ok(done) = done {
            let _ = tx.send(done);
        }
        wake();
    });
    rx
}

#[test]
fn idle_during_job_locks_on_finish() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let (app, clock) = test_app(dir.path());
    let mut harness = harness(app.with_spawner(held_worker));
    harness.run();
    unlock(&mut harness);
    let a = auto_lock(&harness);
    let hold = HOLD_WORKER.lock().unwrap_or_else(PoisonError::into_inner);
    harness.get_by_label("New login").click();
    harness.run();
    type_into(&mut harness, "Title", ROW_TITLE);
    type_into(&mut harness, "Password", SECRET);
    harness.get_by_label("Save").click();
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Working);
    // The idle deadline passes while the job runs (a slow disk, or a sleep).
    clock.advance(a);
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Working);
    drop(hold);
    run_until(
        &mut harness,
        |app| app.screen_kind() != ScreenKind::Working,
        WAIT,
    );
    // The finished job does not count as activity: the vault locks at once.
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert!(!harness.state().is_unlocked());
    assert_eq!(
        harness.state().lock_note(),
        Some(LockNote {
            reason: LockReason::Idle,
            discarded_unsaved: false
        })
    );
    harness.run();
    assert_locked(&harness, &line(LockReason::Idle, false, a));
}
