#![cfg(target_os = "macos")]
//! Manual, idle, minimise and sleep lock, driven headless through the whole app.
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
    FakeClipboard, FakeWindow, PASSWORD, TestClock, harness, harness_with_window, make_vault,
    make_vault_with_auto_lock, make_vault_without_lock_on_sleep, run_until, test_app,
    test_app_with_clipboard, vault_path,
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
    // The window is hidden (covered); a frame still runs with input in it. The harness
    // runs `tick` and `show` together, so this also covers the `visible()` gate in `show`.
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

#[test]
fn job_end_while_minimised_asks_for_another_frame() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let (app, _clock) = test_app(dir.path());
    let window = FakeWindow::default();
    let mut harness = harness_with_window(app.with_spawner(held_worker), window.clone());
    harness.run();
    unlock(&mut harness);
    let hold = HOLD_WORKER.lock().unwrap_or_else(PoisonError::into_inner);
    harness.get_by_label("New login").click();
    harness.run();
    type_into(&mut harness, "Title", ROW_TITLE);
    type_into(&mut harness, "Password", SECRET);
    harness.get_by_label("Save").click();
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Working);
    // The user minimises while the job runs; `tick` only checks it with the vault open.
    window.set_minimised(true);
    drop(hold);
    // Only `tick`, as eframe's `logic` while the window is hidden. The tick that takes
    // the answer must ask for another frame, or the minimise lock waits for the next
    // wake-up (up to a second, or never if the window stays hidden).
    let start = std::time::Instant::now();
    loop {
        let ctx = eframe::egui::Context::default();
        // Count immediate repaint requests (zero delay) made by the tick.
        let asked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = asked.clone();
        ctx.set_request_repaint_callback(move |info| {
            if info.delay.is_zero() {
                seen.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
        harness.state_mut().tick(&ctx, &window);
        if harness.state().screen_kind() != ScreenKind::Working {
            assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
            assert!(asked.load(std::sync::atomic::Ordering::SeqCst));
            break;
        }
        assert!(start.elapsed() < WAIT, "job did not end");
        std::thread::sleep(Duration::from_millis(10));
    }
    harness
        .state_mut()
        .tick(&eframe::egui::Context::default(), &window);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
}

/// An app on the vault already in `dir` (made by the caller), with a window the test
/// can post OS events to, unlocked and holding one login.
fn open_made_in_window(dir: &Path) -> (Harness<'static, HolmApp>, TestClock, FakeWindow) {
    let (app, clock) = test_app(dir);
    let window = FakeWindow::default();
    let mut harness = harness_with_window(app, window.clone());
    harness.run();
    unlock(&mut harness);
    add_example(&mut harness);
    assert!(nodes_with(&harness, ROW_TITLE) > 0, "the row is drawn");
    (harness, clock, window)
}

/// A sleep, screen lock or logout event locks in the frame that reads it, before the
/// vault rows are drawn.
#[test]
fn os_lock_event_locks_before_draw() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let (mut harness, _clock, window) = open_made_in_window(dir.path());
    window.post_os_lock_event();
    // One frame: `tick` reads the event and locks, then `show` draws the unlock screen.
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert!(!harness.state().is_unlocked());
    assert_eq!(
        harness.state().lock_note(),
        Some(LockNote {
            reason: LockReason::Sleep,
            discarded_unsaved: false
        })
    );
    assert_eq!(
        nodes_with(&harness, ROW_TITLE),
        0,
        "no row drawn that frame"
    );
    harness.run();
    assert_locked(&harness, messages::LOCKED_SLEEP);
}

/// The wall clock gaining on the monotonic clock (the Mac slept, with no event seen)
/// locks too, well before the auto-lock time.
#[test]
fn wall_jump_locks_gui() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let (mut harness, clock, _window) = open_made_in_window(dir.path());
    assert!(auto_lock(&harness) > Duration::from_secs(60));
    clock.sleep(Duration::from_secs(60));
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert_eq!(
        harness.state().lock_note().map(|n| n.reason),
        Some(LockReason::Sleep)
    );
    assert_eq!(nodes_with(&harness, ROW_TITLE), 0);
    harness.run();
    assert_locked(&harness, messages::LOCKED_SLEEP);
}

/// With `lock_on_sleep` off, neither the OS event nor a wall-clock jump locks.
#[test]
fn lock_on_sleep_false_ignores_event() {
    let dir = tempfile::tempdir().unwrap();
    make_vault_without_lock_on_sleep(dir.path(), PASSWORD);
    let (mut harness, clock, window) = open_made_in_window(dir.path());
    window.post_os_lock_event();
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    clock.sleep(Duration::from_secs(60));
    harness.step();
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    assert!(harness.state().is_unlocked());
    assert_eq!(harness.state().lock_note(), None);
    assert!(
        nodes_with(&harness, ROW_TITLE) > 0,
        "the row is still drawn"
    );
}

/// A sleep lock clears a copied password at once, through the pending clear, well
/// before its clear time.
#[test]
fn sleep_lock_clears_clipboard() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let fake = FakeClipboard::default();
    let (app, clock) = test_app_with_clipboard(dir.path(), Box::new(fake.clone()));
    let window = FakeWindow::default();
    let mut harness = harness_with_window(app, window.clone());
    harness.run();
    unlock(&mut harness);
    add_example(&mut harness);
    harness.get_by_label("Copy").click();
    harness.run();
    assert_eq!(fake.0.borrow().contents.as_deref(), Some(SECRET));
    // Ten seconds asleep: less than the clear time, so only the sleep clears it.
    clock.sleep(Duration::from_secs(10));
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert_eq!(fake.0.borrow().clears, 1);
    assert_eq!(fake.0.borrow().contents, None);
    // The OS event path clears too (nothing left to clear now, so no second clear).
    window.post_os_lock_event();
    harness.step();
    assert_eq!(fake.0.borrow().clears, 1);
}

/// A sleep longer than the auto-lock time is still a sleep lock: the sleep check
/// comes before the idle check.
#[test]
fn long_sleep_says_sleep_not_idle() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let (mut harness, clock, _window) = open_made_in_window(dir.path());
    let a = auto_lock(&harness);
    clock.sleep(a + Duration::from_secs(60));
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert_eq!(
        harness.state().lock_note().map(|n| n.reason),
        Some(LockReason::Sleep)
    );
    harness.run();
    assert_locked(&harness, messages::LOCKED_SLEEP);
}

/// A sleep seen while a save runs on the worker clears the clipboard at once and
/// locks as soon as the answer is in, before the vault is drawn again.
#[test]
fn sleep_during_job_locks_when_job_ends() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let fake = FakeClipboard::default();
    let (app, _clock) = test_app_with_clipboard(dir.path(), Box::new(fake.clone()));
    let window = FakeWindow::default();
    let mut harness = harness_with_window(app.with_spawner(held_worker), window.clone());
    harness.run();
    unlock(&mut harness);
    add_example(&mut harness);
    harness.get_by_label("Copy").click();
    harness.run();
    assert_eq!(fake.0.borrow().contents.as_deref(), Some(SECRET));
    let hold = HOLD_WORKER.lock().unwrap_or_else(PoisonError::into_inner);
    harness.get_by_label("New login").click();
    harness.run();
    type_into(&mut harness, "Title", ROW_TITLE);
    type_into(&mut harness, "Password", SECRET);
    harness.get_by_label("Save").click();
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Working);
    window.post_os_lock_event();
    harness.step();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Working);
    // The clipboard is cleared in that frame, while the job still runs.
    assert_eq!(fake.0.borrow().clears, 1);
    assert_eq!(fake.0.borrow().contents, None);
    drop(hold);
    let start = std::time::Instant::now();
    while harness.state().screen_kind() == ScreenKind::Working {
        assert!(start.elapsed() < WAIT, "job did not end");
        std::thread::sleep(Duration::from_millis(10));
        harness.step();
    }
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert_eq!(
        harness.state().lock_note().map(|n| n.reason),
        Some(LockReason::Sleep)
    );
    assert_eq!(
        nodes_with(&harness, ROW_TITLE),
        0,
        "no row drawn after the job"
    );
    harness.run();
    assert_locked(&harness, messages::LOCKED_SLEEP);
}

// ---- Undo memory (Task 8) ----

/// The text now in the field labelled `label`.
fn field_value(harness: &Harness<'static, HolmApp>, label: &str) -> String {
    harness.get_by_label(label).value().unwrap_or_default()
}

/// Types a secret-looking marker into Search and into the import path field.
fn type_in_search_and_import_path(harness: &mut Harness<'static, HolmApp>) {
    type_into(harness, "Search", "EXAMPLE");
    assert_eq!(field_value(harness, "Search"), "EXAMPLE");
    harness.get_by_label("Import...").click();
    harness.run();
    type_into(harness, "File path", "EXAMPLE");
    assert_eq!(field_value(harness, "File path"), "EXAMPLE");
}

/// No text-edit state (undo history) may remain in egui memory after a lock.
fn assert_no_text_state(harness: &Harness<'static, HolmApp>) {
    assert_eq!(
        harness
            .ctx
            .data(|d| d.count::<eframe::egui::text_edit::TextEditState>()),
        0,
        "text-edit state kept while locked"
    );
}

/// After an unlock, Cmd+Z in Search and in the import path field restores nothing.
fn assert_undo_restores_nothing(harness: &mut Harness<'static, HolmApp>) {
    unlock(harness);
    harness.get_by_label("Search").click();
    harness.run();
    harness.key_press_modifiers(Modifiers::COMMAND, Key::Z);
    harness.run();
    assert_eq!(field_value(harness, "Search"), "", "Search undo is empty");
    harness.get_by_label("Import...").click();
    harness.run();
    harness.get_by_label("File path").click();
    harness.run();
    harness.key_press_modifiers(Modifiers::COMMAND, Key::Z);
    harness.run();
    assert_eq!(field_value(harness, "File path"), "", "path undo is empty");
}

#[test]
fn undo_memory_cleared_on_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    type_in_search_and_import_path(&mut harness);
    harness.get_by_label("Lock").click();
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert_no_text_state(&harness);
    assert_undo_restores_nothing(&mut harness);
}

#[test]
fn undo_memory_cleared_on_idle_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, clock) = open(dir.path());
    type_in_search_and_import_path(&mut harness);
    clock.advance(auto_lock(&harness));
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert_no_text_state(&harness);
    assert_undo_restores_nothing(&mut harness);
}

#[test]
fn undo_memory_cleared_on_minimise_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, window) = open_in_window(dir.path());
    type_in_search_and_import_path(&mut harness);
    window.set_minimised(true);
    harness.step();
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert_eq!(
        harness.state().lock_note().map(|n| n.reason),
        Some(LockReason::Minimised)
    );
    assert_no_text_state(&harness);
    window.set_minimised(false);
    harness.run();
    assert_undo_restores_nothing(&mut harness);
}

#[test]
fn undo_memory_cleared_on_sleep_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock, window) = open_in_window(dir.path());
    type_in_search_and_import_path(&mut harness);
    window.post_os_lock_event();
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert_eq!(
        harness.state().lock_note().map(|n| n.reason),
        Some(LockReason::Sleep)
    );
    assert_no_text_state(&harness);
    assert_undo_restores_nothing(&mut harness);
}
