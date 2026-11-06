#![cfg(target_os = "macos")]
//! The import and export screens, driven headless through the whole app.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{
    FakeClipboard, OTHER_PASSWORD, PASSWORD, TestClock, harness, make_vault,
    make_vault_with_auto_lock, run_until, test_app, test_app_with_clipboard_and_dialog,
    test_app_with_dialog,
};
use eframe::egui::{Event, Key, accesskit::Role};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use holm_core::clock::SystemClock;
use holm_core::search::Query;
use holm_core::session::Session;
use holm_crypto::MasterPassword;
use holm_gui::app::{HolmApp, ScreenKind};
use holm_gui::file_dialog::{FileDialog, NoDialog};
use holm_gui::messages;
use holm_platform::fs_store::FsStore;

const WAIT: Duration = Duration::from_secs(60);
const FIXTURE: &str = "../holm-core/tests/fixtures/import/holm.csv";

fn type_into(harness: &mut Harness<'static, HolmApp>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.event(Event::Text(text.to_owned()));
    harness.run();
}

fn vault_screen(app: &HolmApp) -> bool {
    app.screen_kind() == ScreenKind::Vault
}

fn open(dir: &Path) -> (Harness<'static, HolmApp>, TestClock) {
    make_vault(dir, PASSWORD);
    let (app, clock) = test_app(dir);
    unlock(app, clock)
}

/// Unlocks an app on an existing vault and waits for the vault screen.
fn unlock(app: HolmApp, clock: TestClock) -> (Harness<'static, HolmApp>, TestClock) {
    let mut harness = harness(app);
    harness.run();
    type_into(&mut harness, "Master password", PASSWORD);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(&mut harness, vault_screen, WAIT);
    harness.run();
    (harness, clock)
}

fn button(harness: &Harness<'static, HolmApp>, label: &str) -> bool {
    harness
        .query_by_role_and_label(Role::Button, label)
        .is_some()
}

fn click_button(harness: &mut Harness<'static, HolmApp>, label: &str) {
    harness.get_by_role_and_label(Role::Button, label).click();
    harness.run();
}

/// Clicks a button that starts a job and waits for the vault screen again.
fn click_job(harness: &mut Harness<'static, HolmApp>, label: &str) {
    harness.get_by_role_and_label(Role::Button, label).click();
    harness.step();
    run_until(harness, vault_screen, WAIT);
    harness.run();
}

fn disabled(harness: &Harness<'static, HolmApp>, label: &str) -> bool {
    harness
        .get_by_role_and_label(Role::Button, label)
        .accesskit_node()
        .is_disabled()
}

fn has_text(harness: &Harness<'static, HolmApp>, needle: &str) -> bool {
    harness.root().children_recursive().any(|node| {
        let access = node.accesskit_node();
        [access.label(), access.value(), access.description()]
            .iter()
            .flatten()
            .any(|t| t.contains(needle))
    })
}

fn fixture_copy(dir: &Path) -> PathBuf {
    let target = dir.join("source.csv");
    std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE), &target).unwrap();
    target
}

fn start_export(harness: &mut Harness<'static, HolmApp>, path: &Path, password: &str) {
    click_button(harness, "Export...");
    type_into(harness, "File path", path.to_str().unwrap());
    type_into(harness, "Master password to export", password);
    harness
        .get_by_label("I understand this file is not encrypted")
        .click();
    harness.run();
}

#[test]
fn import_preview_then_import_then_warning() {
    let dir = tempfile::tempdir().unwrap();
    let source = fixture_copy(dir.path());
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Import...");
    assert!(disabled(&harness, "Read file"));
    type_into(&mut harness, "File path", source.to_str().unwrap());
    click_job(&mut harness, "Read file");
    assert!(button(&harness, "Import these rows"));
    assert!(has_text(&harness, "Written by: Holm."));
    click_job(&mut harness, "Import these rows");
    assert!(has_text(&harness, "Import finished"));
    assert!(has_text(
        &harness,
        holm_core::import::IMPORT_DELETE_SOURCE_WARNING
    ));
    click_button(&mut harness, "Close");
    // The login from the file is listed.
    assert_eq!(harness.query_all_by_label("Example Portal").count(), 1);
}

#[test]
fn import_oversize_shows_fixed_text() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big.csv");
    std::fs::write(&big, vec![b'a'; 17 * 1024 * 1024]).unwrap();
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", big.to_str().unwrap());
    click_job(&mut harness, "Read file");
    let _ = harness.get_by_label(messages::IMPORT_TOO_BIG);
}

#[test]
fn export_button_needs_password_and_checkbox() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.csv");
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Export...");
    assert!(disabled(&harness, "Export"));
    type_into(&mut harness, "File path", out.to_str().unwrap());
    assert!(disabled(&harness, "Export"));
    type_into(&mut harness, "Master password to export", PASSWORD);
    assert!(disabled(&harness, "Export"));
    harness
        .get_by_label("I understand this file is not encrypted")
        .click();
    harness.run();
    assert!(!disabled(&harness, "Export"));
    assert!(!out.exists());
}

#[test]
fn export_wrong_password_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.csv");
    let (mut harness, _clock) = open(dir.path());
    start_export(&mut harness, &out, OTHER_PASSWORD);
    click_job(&mut harness, "Export");
    let _ = harness.get_by_label(messages::EXPORT_WRONG_PASSWORD);
    assert!(!out.exists());
    assert!(harness.state().secret_buffers_empty());
}

#[test]
fn export_writes_0600_file_that_reimports() {
    let dir = tempfile::tempdir().unwrap();
    let source = fixture_copy(dir.path());
    let out = dir.path().join("out.csv");
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", source.to_str().unwrap());
    click_job(&mut harness, "Read file");
    click_job(&mut harness, "Import these rows");
    click_button(&mut harness, "Close");

    start_export(&mut harness, &out, PASSWORD);
    click_job(&mut harness, "Export");
    assert!(has_text(&harness, "Export finished"));
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("Example Portal"));
    click_button(&mut harness, "Close");

    // The export reads back through the import screen: every row is a duplicate.
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", out.to_str().unwrap());
    click_job(&mut harness, "Read file");
    assert!(has_text(&harness, "Written by: Holm."));
}

#[test]
fn export_existing_path_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.csv");
    std::fs::write(&out, b"keep me").unwrap();
    let (mut harness, _clock) = open(dir.path());
    start_export(&mut harness, &out, PASSWORD);
    click_job(&mut harness, "Export");
    let _ = harness.get_by_label(messages::EXPORT_EXISTS);
    assert_eq!(std::fs::read(&out).unwrap(), b"keep me");
}

#[test]
fn transfer_texts_hold_no_values() {
    let dir = tempfile::tempdir().unwrap();
    let source = fixture_copy(dir.path());
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", source.to_str().unwrap());
    click_job(&mut harness, "Read file");
    for needle in [
        "EXAMPLE-pass-1",
        "example.user",
        "portal.example.com",
        "EXAMPLE-0xaddr01",
        "word00",
        "source.csv",
    ] {
        assert!(!has_text(&harness, needle), "{needle} leaked");
    }
    click_job(&mut harness, "Import these rows");
    for needle in ["EXAMPLE-pass-1", "EXAMPLE-0xaddr01", "word00", "source.csv"] {
        assert!(!has_text(&harness, needle), "{needle} leaked");
    }
}

#[test]
fn import_enabled_when_duplicates_outnumber_new_rows() {
    let dir = tempfile::tempdir().unwrap();
    let source = fixture_copy(dir.path());
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", source.to_str().unwrap());
    click_job(&mut harness, "Read file");
    click_job(&mut harness, "Import these rows");
    click_button(&mut harness, "Close");

    // Four rows are already in the vault, one is new.
    let mut text = std::fs::read_to_string(&source).unwrap();
    text.push_str(
        "Example Extra,extra.user,EXAMPLE-pass-2,https://extra.example.com,,Work,login,,,,\n",
    );
    let mixed = dir.path().join("mixed.csv");
    std::fs::write(&mixed, text).unwrap();
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", mixed.to_str().unwrap());
    click_job(&mut harness, "Read file");
    assert!(!disabled(&harness, "Import these rows"));
    click_job(&mut harness, "Import these rows");
    assert!(has_text(&harness, "1 added."));
    assert!(has_text(&harness, "4 skipped as duplicates."));
}

/// Makes the vault folder read-only for a while; restores it on drop.
struct ReadOnly(PathBuf);

impl ReadOnly {
    fn new(dir: &Path) -> Option<ReadOnly> {
        let folder = dir.join("Holm");
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o500)).unwrap();
        let guard = ReadOnly(folder);
        let probe = guard.0.join("root-probe");
        match std::fs::File::create(&probe) {
            Ok(file) => {
                drop(file);
                std::fs::remove_file(probe).unwrap();
                eprintln!("SKIP: running as root");
                None
            }
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                Some(guard)
            }
        }
    }

    fn restore(&self) {
        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

impl Drop for ReadOnly {
    fn drop(&mut self) {
        self.restore();
    }
}

#[test]
fn import_save_failure_keeps_banner_and_rows() {
    let dir = tempfile::tempdir().unwrap();
    let source = fixture_copy(dir.path());
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", source.to_str().unwrap());
    click_job(&mut harness, "Read file");
    let Some(guard) = ReadOnly::new(dir.path()) else {
        return;
    };
    click_job(&mut harness, "Import these rows");
    // The report is not there; the pane shows the honest text and the banner.
    let _ = harness.get_by_label(messages::IMPORT_UNSAVED);
    let _ = harness.get_by_label(messages::DIR_PERMISSIONS);
    assert!(button(&harness, "Try again"));
    click_button(&mut harness, "Cancel");
    // The items are in the list and the banner stays.
    assert_eq!(harness.query_all_by_label("Example Portal").count(), 1);
    assert!(button(&harness, "Try again"));

    guard.restore();
    click_job(&mut harness, "Try again");
    assert!(!button(&harness, "Try again"));
    assert_eq!(harness.query_all_by_label("Example Portal").count(), 1);
}

#[test]
fn export_throttle_shows_live_wait() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.csv");
    let (mut harness, clock) = open(dir.path());
    start_export(&mut harness, &out, OTHER_PASSWORD);
    click_job(&mut harness, "Export");
    for _ in 0..2 {
        type_into(&mut harness, "Master password to export", OTHER_PASSWORD);
        click_job(&mut harness, "Export");
    }
    let _ = harness.get_by_label("Too many tries. Try again in 2 s.");
    type_into(&mut harness, "Master password to export", PASSWORD);
    assert!(disabled(&harness, "Export"));

    clock.advance(Duration::from_secs(1));
    harness.step();
    let _ = harness.get_by_label("Too many tries. Try again in 1 s.");
    assert!(disabled(&harness, "Export"));

    clock.advance(Duration::from_secs(1));
    harness.step();
    assert!(harness.query_by_label_contains("Try again in").is_none());
    assert!(!disabled(&harness, "Export"));
    assert!(!out.exists());
}

type Done = std::sync::mpsc::Receiver<holm_gui::worker::WorkDone>;
type Wake = Box<dyn Fn() + Send>;

fn done(
    session: holm_core::session::Session<holm_platform::fs_store::FsStore>,
    kind: holm_gui::worker::JobKind,
    transfer: Option<holm_gui::worker::TransferResult>,
) -> Done {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(holm_gui::worker::WorkDone {
        session,
        kind,
        result: Ok(()),
        added: None,
        returned: None,
        transfer,
        phrase: None,
    })
    .unwrap();
    rx
}

/// Real worker for everything except transfer jobs, which come back with no answer.
fn transfer_goes_missing(
    session: holm_core::session::Session<holm_platform::fs_store::FsStore>,
    job: holm_gui::worker::Job,
    wake: Wake,
) -> Done {
    if job.kind().is_transfer() {
        return done(session, job.kind(), None);
    }
    holm_gui::worker::spawn(session, job, wake)
}

static PREVIEWS_SENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn counts_previews(
    session: holm_core::session::Session<holm_platform::fs_store::FsStore>,
    job: holm_gui::worker::Job,
    wake: Wake,
) -> Done {
    if job.kind() == holm_gui::worker::JobKind::PreviewImport {
        PREVIEWS_SENT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    holm_gui::worker::spawn(session, job, wake)
}

static IMPORTS_SEEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The first import runs for real; the second one fails at once without touching the
/// session, as an early failure does.
fn second_import_fails_early(
    session: holm_core::session::Session<holm_platform::fs_store::FsStore>,
    job: holm_gui::worker::Job,
    wake: Wake,
) -> Done {
    if job.kind() == holm_gui::worker::JobKind::Import
        && IMPORTS_SEEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1
    {
        let failed = holm_gui::worker::TransferResult::Failed(
            holm_platform::transfer::TransferError::Core(holm_core::error::CoreError::Locked),
        );
        return done(session, holm_gui::worker::JobKind::Import, Some(failed));
    }
    holm_gui::worker::spawn(session, job, wake)
}

fn open_with(dir: &Path, spawner: holm_gui::worker::Spawner) -> Harness<'static, HolmApp> {
    make_vault(dir, PASSWORD);
    let (app, _clock) = test_app(dir);
    let mut harness = harness(app.with_spawner(spawner));
    harness.run();
    type_into(&mut harness, "Master password", PASSWORD);
    harness.key_press(Key::Enter);
    harness.step();
    run_until(&mut harness, vault_screen, WAIT);
    harness.run();
    harness
}

#[test]
fn export_tick_drawn_above_password() {
    let dir = tempfile::tempdir().unwrap();
    let (mut harness, _clock) = open(dir.path());
    click_button(&mut harness, "Export...");
    let tick = harness
        .get_by_label("I understand this file is not encrypted")
        .rect()
        .min
        .y;
    let password = harness
        .get_by_label("Master password to export")
        .rect()
        .min
        .y;
    assert!(tick < password, "tick {tick} not above password {password}");
}

#[test]
fn busy_resets_when_transfer_missing() {
    let dir = tempfile::tempdir().unwrap();
    let source = fixture_copy(dir.path());
    let mut harness = open_with(dir.path(), transfer_goes_missing);
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", source.to_str().unwrap());
    click_job(&mut harness, "Read file");
    let _ = harness.get_by_label(messages::WORKER_LOST);
    assert!(!button(&harness, "Read file"));
    assert!(button(&harness, "Import..."));
}

#[test]
fn relative_import_path_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut harness = open_with(dir.path(), counts_previews);
    let before = PREVIEWS_SENT.load(std::sync::atomic::Ordering::SeqCst);
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", "source.csv");
    click_button(&mut harness, "Read file");
    let _ = harness.get_by_label(messages::PATH_NOT_ABSOLUTE);
    assert_eq!(
        PREVIEWS_SENT.load(std::sync::atomic::Ordering::SeqCst),
        before
    );
}

#[test]
fn dirty_before_import_not_reported_as_import() {
    let dir = tempfile::tempdir().unwrap();
    let source = fixture_copy(dir.path());
    let mut harness = open_with(dir.path(), second_import_fails_early);
    // First import: rows go in, the save fails, the vault stays dirty.
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", source.to_str().unwrap());
    click_job(&mut harness, "Read file");
    let Some(guard) = ReadOnly::new(dir.path()) else {
        return;
    };
    click_job(&mut harness, "Import these rows");
    click_button(&mut harness, "Cancel");
    assert!(button(&harness, "Try again"));
    guard.restore();

    // Second import fails before it adds anything: it must not claim rows were added.
    let mut text = std::fs::read_to_string(&source).unwrap();
    text.push_str(
        "Example Extra,extra.user,EXAMPLE-pass-2,https://extra.example.com,,Work,login,,,,\n",
    );
    let mixed = dir.path().join("mixed.csv");
    std::fs::write(&mixed, text).unwrap();
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", mixed.to_str().unwrap());
    click_job(&mut harness, "Read file");
    click_job(&mut harness, "Import these rows");
    let _ = harness.get_by_label(messages::IMPORT_FAILED);
    assert!(harness.query_by_label(messages::IMPORT_UNSAVED).is_none());
}

/// An open vault whose file dialog is `make(&clock)`.
fn open_with_dialog(
    dir: &Path,
    make: impl FnOnce(&TestClock) -> Box<dyn FileDialog>,
) -> (Harness<'static, HolmApp>, TestClock) {
    make_vault(dir, PASSWORD);
    let (app, clock) = test_app_with_dialog(dir, make);
    unlock(app, clock)
}

const CHOOSE: &str = "Choose\u{2026}";
const CHOOSING_FILE: &str = "Choosing a file\u{2026}";

#[test]
fn choose_paints_placeholder_first() {
    let dir = tempfile::tempdir().unwrap();
    let dialog = NoDialog::returning(PathBuf::from("/tmp/EXAMPLE.csv"));
    let calls = dialog.counter();
    let (mut harness, _clock) = open_with_dialog(dir.path(), |_| Box::new(dialog));
    click_button(&mut harness, "Import...");
    harness.get_by_role_and_label(Role::Button, CHOOSE).click();
    harness.step();
    // The frame after the click shows only the placeholder, and the dialog is not open.
    assert!(harness.query_all_by_label(CHOOSING_FILE).count() >= 1);
    assert_eq!(harness.query_all_by_label("Search").count(), 0);
    assert_eq!(harness.query_all_by_label("Example Portal").count(), 0);
    assert_eq!(calls.get(), 0);
    harness.step();
    assert_eq!(calls.get(), 1);
}

#[test]
fn chosen_path_fills_field() {
    let dir = tempfile::tempdir().unwrap();
    let dialog = NoDialog::returning(PathBuf::from("/tmp/EXAMPLE-holm-missing.csv"));
    let (mut harness, _clock) = open_with_dialog(dir.path(), |_| Box::new(dialog));
    click_button(&mut harness, "Import...");
    assert!(disabled(&harness, "Read file"));
    harness.get_by_role_and_label(Role::Button, CHOOSE).click();
    harness.run();
    assert!(!disabled(&harness, "Read file"));
    // The preview job runs on the chosen path (no file there, so a fixed error).
    click_job(&mut harness, "Read file");
    let _ = harness.get_by_label(messages::IMPORT_NOT_FOUND);
}

#[test]
fn cancelled_dialog_keeps_form() {
    let dir = tempfile::tempdir().unwrap();
    let dialog = NoDialog::default();
    let calls = dialog.counter();
    let (mut harness, _clock) = open_with_dialog(dir.path(), |_| Box::new(dialog));
    click_button(&mut harness, "Import...");
    harness.get_by_role_and_label(Role::Button, CHOOSE).click();
    harness.run();
    assert_eq!(calls.get(), 1);
    assert!(disabled(&harness, "Read file"));
    assert_eq!(harness.query_all_by_label(CHOOSING_FILE).count(), 0);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
}

#[test]
fn locked_while_choosing_drops_path() {
    let dir = tempfile::tempdir().unwrap();
    seeded_vault(dir.path(), Some(60));
    let source = dir.path().join("source.csv");
    let (app, clock) = test_app_with_dialog(dir.path(), |clock| {
        let clock = clock.clone();
        Box::new(NoDialog::returning(source).with_hook(move || {
            clock.advance(Duration::from_secs(61));
        }))
    });
    let (mut harness, _clock) = unlock(app, clock);
    click_button(&mut harness, "Import...");
    assert_eq!(harness.query_all_by_label("Example Portal").count(), 1);
    harness.get_by_role_and_label(Role::Button, CHOOSE).click();
    harness.run();
    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    // Nothing of the vault or the chosen path is on screen.
    assert_eq!(harness.query_all_by_label("Example Portal").count(), 0);
    assert!(!has_text(&harness, "source.csv"));
    assert!(!button(&harness, "Read file"));
}

#[test]
fn typed_path_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let source = fixture_copy(dir.path());
    let (mut harness, _clock) = open_with_dialog(dir.path(), |_| Box::new(NoDialog::default()));
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", source.to_str().unwrap());
    click_job(&mut harness, "Read file");
    assert!(button(&harness, "Import these rows"));
}

/// A vault holding the fixture's logins (imported through the app, then closed), made
/// with `auto_lock_secs` when given.
fn seeded_vault(dir: &Path, auto_lock_secs: Option<u32>) {
    match auto_lock_secs {
        Some(secs) => make_vault_with_auto_lock(dir, PASSWORD, secs),
        None => make_vault(dir, PASSWORD),
    }
    let source = fixture_copy(dir);
    let (app, clock) = test_app(dir);
    let (mut harness, _clock) = unlock(app, clock);
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", source.to_str().unwrap());
    click_job(&mut harness, "Read file");
    click_job(&mut harness, "Import these rows");
    click_button(&mut harness, "Close");
    assert_eq!(harness.query_all_by_label("Example Portal").count(), 1);
}

#[test]
fn choose_hides_rows_and_detail() {
    let dir = tempfile::tempdir().unwrap();
    seeded_vault(dir.path(), None);
    let dialog = NoDialog::returning(PathBuf::from("/tmp/EXAMPLE.csv"));
    let (app, clock) = test_app_with_dialog(dir.path(), |_| Box::new(dialog));
    let (mut harness, _clock) = unlock(app, clock);
    click_button(&mut harness, "Import...");
    assert_eq!(harness.query_all_by_label("Example Portal").count(), 1);
    harness.get_by_role_and_label(Role::Button, CHOOSE).click();
    harness.step();
    assert!(harness.query_all_by_label(CHOOSING_FILE).count() >= 1);
    assert_eq!(harness.query_all_by_label("Example Portal").count(), 0);
}

#[test]
fn cancel_keeps_typed_path() {
    let dir = tempfile::tempdir().unwrap();
    let source = fixture_copy(dir.path());
    let (mut harness, _clock) = open_with_dialog(dir.path(), |_| Box::new(NoDialog::default()));
    click_button(&mut harness, "Import...");
    type_into(&mut harness, "File path", source.to_str().unwrap());
    assert!(!disabled(&harness, "Read file"));
    harness.get_by_role_and_label(Role::Button, CHOOSE).click();
    harness.run();
    // Cancelled: the typed path is still there, so the form still reads it.
    assert!(!disabled(&harness, "Read file"));
    click_job(&mut harness, "Read file");
    assert!(button(&harness, "Import these rows"));
}

#[test]
fn chosen_existing_export_path_refused_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.csv");
    std::fs::write(&out, b"keep me").unwrap();
    let dialog = NoDialog::returning(out.clone());
    let (mut harness, _clock) = open_with_dialog(dir.path(), |_| Box::new(dialog));
    click_button(&mut harness, "Export...");
    harness.get_by_role_and_label(Role::Button, CHOOSE).click();
    harness.run();
    let _ = harness.get_by_label(messages::EXPORT_EXISTS);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    assert_eq!(std::fs::read(&out).unwrap(), b"keep me");
}

#[test]
fn opening_a_dialog_clears_a_copied_secret() {
    const SECRET: &str = "EXAMPLE-zq9-pass";
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let fake = FakeClipboard::default();
    let seen = std::rc::Rc::new(std::cell::RefCell::new(None));
    let dialog = {
        let fake = fake.clone();
        let seen = std::rc::Rc::clone(&seen);
        NoDialog::default().with_hook(move || {
            let state = fake.0.borrow();
            *seen.borrow_mut() = Some((state.clears, state.contents.clone()));
        })
    };
    let (app, clock) =
        test_app_with_clipboard_and_dialog(dir.path(), Box::new(fake.clone()), |_| {
            Box::new(dialog)
        });
    let (mut harness, _clock) = unlock(app, clock);
    common::new_login(&mut harness);
    harness.run();
    type_into(&mut harness, "Title", "Example Mail");
    type_into(&mut harness, "Password", SECRET);
    harness.get_by_label("Save").click();
    harness.step();
    run_until(&mut harness, vault_screen, WAIT);
    harness.run();
    harness.get_by_label("Copy").click();
    harness.run();
    assert_eq!(fake.0.borrow().contents.as_deref(), Some(SECRET));

    click_button(&mut harness, "Import...");
    harness.get_by_role_and_label(Role::Button, CHOOSE).click();
    harness.run();
    // Inside the dialog call the clipboard was already clear.
    assert_eq!(*seen.borrow(), Some((1, None)));
}

const BACKUP_OPEN: &str = messages::BACKUP_BUTTON;

fn start_backup(harness: &mut Harness<'static, HolmApp>, path: &Path) {
    click_button(harness, BACKUP_OPEN);
    type_into(harness, "File path", path.to_str().unwrap());
}

fn open_backup(path: &Path) -> Session<FsStore> {
    let mut copy = Session::new(
        FsStore::new(path.to_path_buf()),
        Box::new(SystemClock::new()),
    );
    copy.unlock(&MasterPassword::new(PASSWORD.to_owned()))
        .unwrap();
    copy
}

fn count_items(session: &Session<FsStore>) -> usize {
    session.search(&Query::default()).unwrap().len()
}

#[test]
fn backup_button_writes_encrypted_copy() {
    let dir = tempfile::tempdir().unwrap();
    seeded_vault(dir.path(), None);
    let out = dir.path().join("copy.holm");
    let (app, clock) = test_app(dir.path());
    let (mut harness, _clock) = unlock(app, clock);
    start_backup(&mut harness, &out);
    click_job(&mut harness, "Back up");
    let _ = harness.get_by_label(messages::BACKUP_DONE);
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    // The copy opens with the same master password and holds the same items.
    let original = open_backup(&common::vault_path(dir.path()));
    let copy = open_backup(&out);
    assert!(count_items(&original) > 0);
    assert_eq!(count_items(&copy), count_items(&original));
}

#[test]
fn backup_refuses_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("copy.holm");
    std::fs::write(&out, b"keep me").unwrap();
    let (mut harness, _clock) = open(dir.path());
    start_backup(&mut harness, &out);
    click_job(&mut harness, "Back up");
    let _ = harness.get_by_label(messages::EXPORT_EXISTS);
    assert_eq!(std::fs::read(&out).unwrap(), b"keep me");
}

#[test]
fn backup_holds_no_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    seeded_vault(dir.path(), None);
    let out = dir.path().join("copy.holm");
    let (app, clock) = test_app(dir.path());
    let (mut harness, _clock) = unlock(app, clock);
    start_backup(&mut harness, &out);
    click_job(&mut harness, "Back up");
    let _ = harness.get_by_label(messages::BACKUP_DONE);
    let bytes = std::fs::read(&out).unwrap();
    assert!(!bytes.is_empty());
    assert!(!bytes.windows(7).any(|w| w == b"EXAMPLE"));
    assert!(!bytes.windows(14).any(|w| w == b"Example Portal"));
}

#[test]
fn backup_choose_fills_path_and_refuses_existing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("copy.holm");
    std::fs::write(&out, b"keep me").unwrap();
    let dialog = NoDialog::returning(out.clone());
    let (mut harness, _clock) = open_with_dialog(dir.path(), |_| Box::new(dialog));
    click_button(&mut harness, BACKUP_OPEN);
    assert!(disabled(&harness, "Back up"), "no path yet");
    harness.get_by_role_and_label(Role::Button, CHOOSE).click();
    harness.run();
    assert!(
        !disabled(&harness, "Back up"),
        "the chosen path fills the field"
    );
    let _ = harness.get_by_label(messages::EXPORT_EXISTS);
    assert_eq!(harness.state().screen_kind(), ScreenKind::Vault);
    assert_eq!(std::fs::read(&out).unwrap(), b"keep me");
}
