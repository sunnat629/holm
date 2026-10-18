//! The app: owns the session, the instance lock and the current screen.
//!
//! [`HolmApp`] is the only owner of the [`Session`], which is the only way into
//! `holm-core`. While Argon2 runs the session lives on the worker thread
//! ([`crate::worker`]) and `HolmApp::session` is `None`; the worker hands it back in its
//! answer. The UI thread never runs Argon2 and never blocks on the worker: it polls the
//! answer channel with `try_recv` once per frame.
//!
//! Locking ([`HolmApp::lock`]) wipes the session's keys and data in the core and
//! replaces the vault screen with an empty unlock form, which drops the vault view and
//! everything it holds. [`HolmApp::tick`] runs the idle and minimise checks even in
//! frames that draw nothing.

use core::fmt;
use std::path::PathBuf;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use eframe::egui;
use holm_core::clock::Clock;
use holm_core::error::CoreError;
use holm_core::session::Session;
use holm_core::settings::{
    AUTO_LOCK_DEFAULT_SECS, AUTO_LOCK_MAX_SECS, AUTO_LOCK_MIN_SECS, CLIPBOARD_DEFAULT_SECS,
    CLIPBOARD_MAX_SECS, CLIPBOARD_MIN_SECS,
};
use holm_core::throttle::ThrottleStatus;
use holm_crypto::kdf::KdfParams;
use holm_platform::clip_clear::{ClearOutcome, PendingClear};
use holm_platform::fs_store::FsStore;
use holm_platform::lock::{self, InstanceLock, LockError};
use holm_platform::paths;

use crate::clipboard::SecretClipboard;
use crate::messages;
pub use crate::messages::{LockNote, LockReason};
use crate::screens::create::CreateForm;
use crate::screens::unlock::UnlockForm;
use crate::screens::vault::VaultAction;
use crate::screens::{FieldFocus, FieldIo, Screen, VaultView};
use crate::worker::{self, Job, JobKind, Spawner, WorkDone};

/// How often the UI polls a running worker, in case its wake-up repaint is missed.
const WORKER_POLL: Duration = Duration::from_millis(200);
/// How long before the idle lock the status bar starts its warning.
const IDLE_WARNING: Duration = Duration::from_secs(30);
/// How often an open vault's frame runs without input: the idle check and countdowns.
const OPEN_TICK: Duration = Duration::from_secs(1);
/// The lock shortcut, Cmd+L.
const LOCK_SHORTCUT: egui::KeyboardShortcut =
    egui::KeyboardShortcut::new(egui::Modifiers::COMMAND, egui::Key::L);

/// Everything the app needs from outside: where the vault is, how hard Argon2 works
/// for a new vault, the clocks, and the clipboard.
pub struct AppConfig {
    /// The vault file.
    pub vault_path: PathBuf,
    /// Argon2 costs for a new vault.
    pub kdf: KdfParams,
    /// The session's clock (throttle and idle lock).
    pub session_clock: Box<dyn Clock>,
    /// The UI's clock (clipboard timer and lock notes in later tasks).
    pub ui_clock: Box<dyn Clock>,
    /// The clipboard for copied secrets and pastes.
    pub clipboard: Box<dyn SecretClipboard>,
}

/// Where the app learns whether its window is minimised. eframe's own
/// `ViewportInfo::minimized` is read on macOS only when the window is created, so it
/// never changes when the user minimises; eframe's `logic` passes [`AppKitWindow`],
/// and tests pass a fake.
pub trait WindowState {
    /// `Some(true)` when the window is minimised, `None` when that is unknown.
    fn minimised(&self) -> Option<bool>;
}

/// The real window, asked through AppKit (`NSWindow.isMiniaturized`).
pub struct AppKitWindow<'a>(pub &'a eframe::Frame);

impl WindowState for AppKitWindow<'_> {
    fn minimised(&self) -> Option<bool> {
        holm_platform::window::is_minimised(self.0)
    }
}

/// Which screen is showing, without its data. For tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenKind {
    /// Choosing a master password.
    Create,
    /// Typing the master password.
    Unlock,
    /// Argon2 is running on the worker.
    Working,
    /// The vault is open.
    Vault,
    /// Holm can't go on; fixed text only.
    Fatal,
}

/// The Holm app. `Debug` shows the screen kind only.
pub struct HolmApp {
    /// The session. `None` while the worker owns it, and when start-up failed.
    session: Option<Session<FsStore>>,
    /// The lock on the vault folder, held for the life of the app and released when
    /// the app drops.
    instance_lock: Option<InstanceLock>,
    /// The screen showing now.
    screen: Screen,
    /// Argon2 costs for a new vault.
    kdf: KdfParams,
    /// The UI's clock.
    ui_clock: Box<dyn Clock>,
    /// The clipboard for copied secrets and pastes. The only clipboard the app uses.
    clipboard: Box<dyn SecretClipboard>,
    /// Which kind of field had focus at the end of the last frame, for
    /// [`raw_input_hook`](eframe::App::raw_input_hook), which runs before the next one.
    focus: FieldFocus,
    /// Where the vault file is, to see whether a failed create left one behind.
    vault_path: PathBuf,
    /// Starts the worker: [`worker::spawn`], or a fake in tests.
    spawner: Spawner,
    /// UI clock time of the last activity noted in the session. Mirrors the session's
    /// idle timer (monotonic part only) for the warning; the lock itself always asks
    /// the session.
    last_activity: Duration,
    /// A copied password waiting for its clipboard clear.
    pending_clear: Option<PendingClear>,
    /// Why the vault last locked, until the next unlock.
    lock_note: Option<LockNote>,
    /// The unlock screen's line for `lock_note`.
    lock_line: Option<String>,
}

impl fmt::Debug for HolmApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HolmApp")
            .field("screen", &self.screen_kind())
            .finish_non_exhaustive()
    }
}

/// [`worker::spawn`] with a boxed wake function, as a [`Spawner`].
fn spawn_worker(
    session: Session<FsStore>,
    job: Job,
    wake: Box<dyn Fn() + Send>,
) -> std::sync::mpsc::Receiver<WorkDone> {
    worker::spawn(session, job, wake)
}

impl HolmApp {
    /// Opens the app on `config.vault_path`.
    ///
    /// In order: make sure the vault folder exists with safe permissions; take the
    /// folder's instance lock (another Holm holding it stops here, before any vault is
    /// read); then show the unlock screen if anything at all is at the vault path (a
    /// file, a symlink or anything else), else the create screen. A failure shows a
    /// fixed line on the fatal screen.
    #[must_use]
    pub fn new(config: AppConfig) -> HolmApp {
        let AppConfig {
            vault_path,
            kdf,
            session_clock,
            ui_clock,
            clipboard,
        } = config;
        let mut app = HolmApp {
            session: None,
            instance_lock: None,
            screen: Screen::Fatal(messages::DIR_ERROR),
            kdf,
            ui_clock,
            clipboard,
            focus: FieldFocus::None,
            vault_path: vault_path.clone(),
            spawner: spawn_worker,
            last_activity: Duration::ZERO,
            pending_clear: None,
            lock_note: None,
            lock_line: None,
        };
        if let Err(e) = paths::ensure_vault_dir(&vault_path) {
            app.screen = Screen::Fatal(messages::dir_error(e));
            return app;
        }
        let Some(dir) = vault_path.parent() else {
            return app;
        };
        match lock::acquire(dir) {
            Ok(held) => app.instance_lock = Some(held),
            Err(LockError::Held) => {
                app.screen = Screen::Fatal(messages::ALREADY_OPEN);
                return app;
            }
            Err(LockError::Io(_)) => return app,
        }
        let exists = std::fs::symlink_metadata(&vault_path).is_ok();
        app.session = Some(Session::new(FsStore::new(vault_path), session_clock));
        app.screen = if exists {
            Screen::Unlock(UnlockForm::new())
        } else {
            Screen::Create(CreateForm::new())
        };
        app
    }

    /// Replaces the worker spawner. For tests that need a worker that fails or waits;
    /// built only with the `test-hooks` feature.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn with_spawner(mut self, spawner: Spawner) -> HolmApp {
        self.spawner = spawner;
        self
    }

    /// Locks the vault: the core wipes its keys and data, and the vault screen is
    /// replaced by an empty unlock form, which drops the vault view (its rows, any open
    /// form and its secret buffer, and the reveal state). The unlock screen then says
    /// why it locked. Does nothing unless the vault screen is showing: while the worker
    /// runs, nothing is open to lock.
    pub fn lock(&mut self, reason: LockReason) {
        if !matches!(self.screen, Screen::Vault(_)) {
            return;
        }
        let auto_lock = self.auto_lock_time();
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let outcome = session.lock();
        self.run_pending_clear();
        self.screen = Screen::Unlock(UnlockForm::new());
        self.focus = FieldFocus::None;
        let note = LockNote {
            reason,
            discarded_unsaved: outcome.discarded_unsaved,
        };
        self.lock_line = Some(messages::lock_line(&note, auto_lock));
        self.lock_note = Some(note);
    }

    /// Runs the waiting clipboard clear now, if any: clears the clipboard when it still
    /// holds the copied password, leaves it alone when something else is there. The
    /// vault screen, if showing, says so. Safe to call on any screen.
    fn run_pending_clear(&mut self) {
        let Some(pending) = self.pending_clear.take() else {
            return;
        };
        let outcome = pending.run(&mut *self.clipboard);
        let note = match outcome {
            ClearOutcome::LeftAlone => Some(messages::CLIPBOARD_CHANGED.to_owned()),
            // Same as the CLI, where this is an error: the password is still there.
            // No retry: the value is wiped with the pending clear, and the line tells
            // the user to replace the clipboard themselves.
            ClearOutcome::StillThere => Some(messages::CLIPBOARD_NOT_CLEARED.to_owned()),
            _ => None,
        };
        if let Screen::Vault(view) = &mut self.screen {
            view.set_copy_note(note);
        }
    }

    /// The vault's clipboard time from its settings, clamped to the settings range.
    fn clipboard_clear_secs(&self) -> u32 {
        self.session
            .as_ref()
            .and_then(|s| s.settings().ok())
            .map_or(CLIPBOARD_DEFAULT_SECS, |s| s.clipboard_clear_secs)
            .clamp(CLIPBOARD_MIN_SECS, CLIPBOARD_MAX_SECS)
    }

    /// The vault's auto-lock time from its settings, clamped to the settings range as
    /// the core's idle timer clamps it. The default while no vault is open.
    #[must_use]
    pub fn auto_lock_time(&self) -> Duration {
        let secs = self
            .session
            .as_ref()
            .and_then(|s| s.settings().ok())
            .map_or(AUTO_LOCK_DEFAULT_SECS, |s| s.auto_lock_secs)
            .clamp(AUTO_LOCK_MIN_SECS, AUTO_LOCK_MAX_SECS);
        Duration::from_secs(u64::from(secs))
    }

    /// Why the vault last locked, until the next unlock. For tests.
    #[doc(hidden)]
    #[must_use]
    pub fn lock_note(&self) -> Option<LockNote> {
        self.lock_note
    }

    /// Per-frame work before drawing. eframe runs it even while the window is hidden,
    /// so the idle lock never waits for a drawn frame. With the vault open it locks at
    /// once when `window` says it is minimised (eframe's own field only when `window`
    /// does not know), or when the session's idle timer has run out (which also covers
    /// a Mac waking from sleep, through the wall-clock gap); otherwise it asks for a
    /// frame every second. It also takes the worker's answer when it is there. It never
    /// records activity: input seen here may be stale.
    pub fn tick(&mut self, ctx: &egui::Context, window: &dyn WindowState) {
        if let Some(pending) = &self.pending_clear {
            if pending.is_due(&*self.ui_clock) {
                self.run_pending_clear();
            } else {
                // The clear must not wait for input: ask for a frame at its deadline.
                let left = pending
                    .due()
                    .saturating_sub(self.ui_clock.monotonic())
                    .max(Duration::from_millis(50));
                ctx.request_repaint_after(left.min(OPEN_TICK));
            }
        }
        if matches!(self.screen, Screen::Vault(_)) {
            let minimised = window
                .minimised()
                .or_else(|| ctx.input(|i| i.viewport().minimized));
            if minimised == Some(true) {
                self.lock(LockReason::Minimised);
            } else if self.session.as_ref().is_some_and(Session::idle_expired) {
                self.lock(LockReason::Idle);
            }
        }
        let throttle_wait = self.throttle_status().retry_after;
        let polled = match &mut self.screen {
            Screen::Working { rx, .. } => Some(rx.try_recv()),
            Screen::Unlock(_) => {
                if let Some(wait) = self.throttle_status().retry_after {
                    ctx.request_repaint_after(until_next_second(wait));
                }
                None
            }
            Screen::Vault(view) => {
                let now = self.ui_clock.monotonic();
                let focused = ctx.input(|i| i.viewport().focused != Some(false));
                view.tick(now, focused);
                // A running export throttle needs a frame at each whole second.
                let next = throttle_wait.map_or(OPEN_TICK, |w| until_next_second(w).min(OPEN_TICK));
                ctx.request_repaint_after(next);
                None
            }
            Screen::Create(_) | Screen::Fatal(_) => None,
        };
        match polled {
            None => {}
            Some(Ok(done)) => {
                self.finish(done);
                // The new screen may need checking at once (minimised or idle while the
                // job ran), and a hidden window draws no frame of its own.
                ctx.request_repaint();
            }
            Some(Err(TryRecvError::Empty)) => ctx.request_repaint_after(WORKER_POLL),
            // The worker ended without an answer: it took the session with it. The
            // vault file is untouched (create writes only after Argon2 succeeds).
            Some(Err(TryRecvError::Disconnected)) => {
                self.screen = Screen::Fatal(messages::WORKER_LOST);
            }
        }
    }

    /// Draws the current screen, and starts the worker when a form submits. With the
    /// vault open it first notes activity and handles Cmd+L.
    pub fn show(&mut self, ui: &mut egui::Ui) {
        if matches!(self.screen, Screen::Vault(_)) {
            self.record_activity(ui.ctx());
            if ui.ctx().input_mut(|i| i.consume_shortcut(&LOCK_SHORTCUT)) {
                self.request_lock();
            }
        }
        let throttle = self.throttle_status();
        let kdf = self.kdf;
        let now = self.ui_clock.monotonic();
        let idle_left = self.idle_left(now);
        let clear_secs = self.clipboard_clear_secs();
        let screen = &mut self.screen;
        let session = self.session.as_ref();
        let lock_line = self.lock_line.as_deref();
        let mut io = FieldIo {
            clipboard: &mut *self.clipboard,
            focus: FieldFocus::None,
            clear_secs,
            copied: None,
        };
        if let Screen::Vault(view) = screen {
            let action = view.show(ui, session, now, idle_left, &throttle, &mut io);
            self.focus = io.focus;
            if let Some(copied) = io.copied.take() {
                self.pending_clear = Some(PendingClear::new(copied, clear_secs, &*self.ui_clock));
            }
            match action {
                None => return,
                Some(VaultAction::Job(job)) => self.start(ui.ctx(), job),
                Some(VaultAction::Lock) => self.request_lock(),
                Some(VaultAction::SaveAndLock) => self.save_and_lock(),
                Some(VaultAction::LockAnyway) => self.lock(LockReason::Manual),
            }
            // This pass drew the vault; if the screen changed, draw the new one instead.
            if !matches!(self.screen, Screen::Vault(_)) {
                ui.ctx().request_discard("the screen changed");
            }
            return;
        }
        let job = egui::CentralPanel::default()
            .show(ui, |ui| match screen {
                Screen::Create(form) => form
                    .show(ui, &mut io)
                    .map(|password| Job::Create(password, kdf)),
                Screen::Unlock(form) => form
                    .show(ui, &mut io, &throttle, lock_line)
                    .map(Job::Unlock),
                Screen::Working { job, .. } => {
                    ui.heading(match job {
                        JobKind::Create => "Creating your vault. This takes a moment.",
                        JobKind::Unlock => "Unlocking. This takes a moment.",
                        JobKind::Add | JobKind::Update | JobKind::Save => "Saving.",
                        JobKind::PreviewImport => "Reading the file.",
                        JobKind::Import => "Importing. This takes a moment.",
                        JobKind::Export => "Exporting. This takes a moment.",
                    });
                    None
                }
                Screen::Vault(_) => None,
                Screen::Fatal(text) => {
                    ui.label(*text);
                    None
                }
            })
            .inner;
        self.focus = io.focus;
        if let Some(job) = job {
            self.start(ui.ctx(), job);
            // This pass drew the form that just went away; draw the new screen
            // instead, so no frame shows (or publishes) a form that no longer exists.
            ui.ctx().request_discard("the screen changed");
        }
    }

    /// Which screen is showing.
    #[must_use]
    pub fn screen_kind(&self) -> ScreenKind {
        match self.screen {
            Screen::Create(_) => ScreenKind::Create,
            Screen::Unlock(_) => ScreenKind::Unlock,
            Screen::Working { .. } => ScreenKind::Working,
            Screen::Vault(_) => ScreenKind::Vault,
            Screen::Fatal(_) => ScreenKind::Fatal,
        }
    }

    /// Whether the app holds an unlocked session.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.session.as_ref().is_some_and(Session::is_unlocked)
    }

    /// Whether no secret buffer holds a character: true when no form is showing, or
    /// when every field of the form is empty.
    #[must_use]
    pub fn secret_buffers_empty(&self) -> bool {
        match &self.screen {
            Screen::Create(form) => form.buffers_empty(),
            Screen::Unlock(form) => form.buffers_empty(),
            Screen::Vault(view) => view.buffers_empty(),
            Screen::Working { .. } | Screen::Fatal(_) => true,
        }
    }

    /// How many characters the current form's secret buffers hold. For tests.
    #[doc(hidden)]
    #[must_use]
    pub fn secret_char_count(&self) -> usize {
        match &self.screen {
            Screen::Create(form) => form.password.char_count() + form.confirm.char_count(),
            Screen::Unlock(form) => form.password.char_count(),
            Screen::Vault(view) => view.secret_char_count(),
            Screen::Working { .. } | Screen::Fatal(_) => 0,
        }
    }

    /// A manual lock (the Lock button or Cmd+L): locks at once, or opens the dialog
    /// first when the session has unsaved changes.
    fn request_lock(&mut self) {
        if self.session.as_ref().is_some_and(Session::is_dirty) {
            if let Screen::Vault(view) = &mut self.screen {
                view.ask_before_lock();
            }
        } else {
            self.lock(LockReason::Manual);
        }
    }

    /// The lock dialog's "Save and lock": saves, then locks. A failed save closes the
    /// dialog, shows the failed-save banner and leaves the vault open.
    fn save_and_lock(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        match session.save() {
            Ok(()) => self.lock(LockReason::Manual),
            Err(e) => {
                if let Screen::Vault(view) = &mut self.screen {
                    view.on_lock_save_failed(&e);
                }
            }
        }
    }

    /// Notes activity in the session when this frame has input events or pointer
    /// movement and the window is not known to be hidden. Called from `show` only,
    /// never from `tick`.
    fn record_activity(&mut self, ctx: &egui::Context) {
        let active = ctx.input(|i| {
            i.viewport().visible() != Some(false)
                && (!i.events.is_empty() || i.pointer.delta() != egui::Vec2::ZERO)
        });
        if active && let Some(session) = self.session.as_mut() {
            session.note_activity();
            self.last_activity = self.ui_clock.monotonic();
        }
    }

    /// Time left before the idle lock, when it is within [`IDLE_WARNING`]. Counted on
    /// the UI clock from the last noted activity, so a sleep can lock without a warning
    /// (the session's wall-clock check), never the other way round.
    fn idle_left(&self, now: Duration) -> Option<Duration> {
        if !matches!(self.screen, Screen::Vault(_)) {
            return None;
        }
        let idle = now.saturating_sub(self.last_activity);
        let left = self.auto_lock_time().saturating_sub(idle);
        (left <= IDLE_WARNING).then_some(left)
    }

    /// The session's throttle status, or no failures while there is no session.
    fn throttle_status(&self) -> ThrottleStatus {
        self.session
            .as_ref()
            .map_or(NO_FAILURES, Session::throttle_status)
    }

    /// Moves the session and `job` to the worker and shows the working screen. The form
    /// (already emptied by its submit) drops here.
    fn start(&mut self, ctx: &egui::Context, job: Job) {
        let Some(session) = self.session.take() else {
            self.screen = Screen::Fatal(messages::WORKER_LOST);
            return;
        };
        let kind = job.kind();
        let keep = match core::mem::replace(&mut self.screen, Screen::Fatal(messages::WORKER_LOST))
        {
            Screen::Vault(view) => Some(view),
            _ => None,
        };
        let ctx = ctx.clone();
        let rx = (self.spawner)(session, job, Box::new(move || ctx.request_repaint()));
        self.screen = Screen::Working {
            job: kind,
            rx,
            keep,
        };
    }

    /// Takes the session back from the worker and moves to the next screen.
    fn finish(&mut self, done: WorkDone) {
        let WorkDone {
            mut session,
            kind,
            result,
            added,
            returned,
            transfer,
        } = done;
        let keep = match core::mem::replace(&mut self.screen, Screen::Fatal(messages::WORKER_LOST))
        {
            Screen::Working { keep, .. } => keep,
            _ => None,
        };
        if matches!(kind, JobKind::Add | JobKind::Update | JobKind::Save) || kind.is_transfer() {
            let mut view = keep.unwrap_or_else(VaultView::new);
            // `tick` skips the idle check while a job runs. Ask now, before the
            // finished job counts as activity, so an idle deadline or a sleep during
            // the job still locks.
            let expired = session.idle_expired();
            if result.is_ok() && !expired {
                session.note_activity();
                self.last_activity = self.ui_clock.monotonic();
            }
            view.on_done(kind, &result, added, returned, &session);
            view.on_transfer_done(kind, transfer, &session);
            self.screen = Screen::Vault(view);
            self.session = Some(session);
            if expired {
                self.lock(LockReason::Idle);
            }
            return;
        }
        self.screen = match (kind, result) {
            (_, Ok(())) => {
                session.note_activity();
                self.last_activity = self.ui_clock.monotonic();
                self.lock_note = None;
                self.lock_line = None;
                Screen::Vault(VaultView::new())
            }
            // Another process made the vault after this app showed Create.
            (JobKind::Create, Err(CoreError::VaultExists)) => Screen::Unlock(UnlockForm::new()),
            // The file was written but the folder sync failed: the vault may exist, and a
            // retry would spend another Argon2 run to land on Unlock anyway.
            (JobKind::Create, Err(CoreError::Store(_)))
                if std::fs::symlink_metadata(&self.vault_path).is_ok() =>
            {
                Screen::Unlock(UnlockForm::with_error(Some(messages::CREATE_MAYBE_SAVED)))
            }
            (JobKind::Create, Err(e)) => {
                Screen::Create(CreateForm::with_error(messages::create_error(&e)))
            }
            // The throttle line already says how long to wait.
            (JobKind::Unlock, Err(CoreError::Throttled { .. })) => {
                Screen::Unlock(UnlockForm::with_error(None))
            }
            (JobKind::Unlock, Err(e)) => {
                Screen::Unlock(UnlockForm::with_error(Some(messages::unlock_error(&e))))
            }
            // Not reached: item jobs only finish with the vault open, and that case
            // returned above. Kept so the match stays exhaustive and fails closed.
            (
                JobKind::Add
                | JobKind::Update
                | JobKind::Save
                | JobKind::PreviewImport
                | JobKind::Import
                | JobKind::Export,
                Err(_),
            ) => Screen::Fatal(messages::WORKER_LOST),
        };
        self.session = Some(session);
    }
}

/// A status with no failures and no wait.
const NO_FAILURES: ThrottleStatus = ThrottleStatus {
    consecutive_failures: 0,
    retry_after: None,
};

/// How long until the whole-second countdown for `wait` changes: the part below a
/// whole second, or a full second when `wait` is whole.
fn until_next_second(wait: Duration) -> Duration {
    match wait.subsec_nanos() {
        0 => Duration::from_secs(1),
        nanos => Duration::from_nanos(u64::from(nanos)),
    }
}

/// Whether `event` is a Cmd+V press (a key repeat counts: one paste per press).
fn is_paste_key(event: &egui::Event) -> bool {
    matches!(
        event,
        egui::Event::Key {
            key: egui::Key::V,
            pressed: true,
            modifiers,
            ..
        } if modifiers.command
    )
}

impl eframe::App for HolmApp {
    /// Quitting clears a waiting copied password first.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.run_pending_clear();
    }

    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.tick(ctx, &AppKitWindow(frame));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }

    /// Runs before egui sees a frame's input. Copy and cut events are dropped, so
    /// nothing in the window is copied except through the Copy button (egui makes none
    /// itself, because `clipboard_shortcuts` is off; this holds even if one arrives).
    ///
    /// When a plain field (title, username, web address) had focus last frame, each
    /// Cmd+V press gets an `Event::Paste` with the clipboard's text right after it. The
    /// `Zeroizing` copy is wiped here; egui's `String` copy is not, which is acceptable
    /// for these fields, never for a secret. A secret field pastes by itself (through
    /// [`crate::clipboard::paste_into`]), and with no text field focused the clipboard is
    /// not read at all.
    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw: &mut egui::RawInput) {
        raw.events
            .retain(|e| !matches!(e, egui::Event::Copy | egui::Event::Cut));
        if self.focus != FieldFocus::Plain || !raw.events.iter().any(is_paste_key) {
            return;
        }
        let Some(text) = self.clipboard.get_text() else {
            return;
        };
        let events = core::mem::take(&mut raw.events);
        raw.events.reserve(events.len() + 1);
        for event in events {
            let paste = is_paste_key(&event);
            raw.events.push(event);
            if paste {
                raw.events
                    .push(egui::Event::Paste(text.as_str().to_owned()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn countdown_repaints_at_the_next_whole_second() {
        assert_eq!(
            until_next_second(Duration::from_secs(2)),
            Duration::from_secs(1)
        );
        assert_eq!(
            until_next_second(Duration::from_millis(1_250)),
            Duration::from_millis(250)
        );
        assert_eq!(
            until_next_second(Duration::from_millis(300)),
            Duration::from_millis(300)
        );
    }
}
