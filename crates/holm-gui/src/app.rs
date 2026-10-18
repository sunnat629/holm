//! The app: owns the session, the instance lock and the current screen.
//!
//! [`HolmApp`] is the only owner of the [`Session`], which is the only way into
//! `holm-core`. While Argon2 runs the session lives on the worker thread
//! ([`crate::worker`]) and `HolmApp::session` is `None`; the worker hands it back in its
//! answer. The UI thread never runs Argon2 and never blocks on the worker: it polls the
//! answer channel with `try_recv` once per frame.

use core::fmt;
use std::path::PathBuf;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use eframe::egui;
use holm_core::clock::Clock;
use holm_core::error::CoreError;
use holm_core::session::Session;
use holm_core::throttle::ThrottleStatus;
use holm_crypto::kdf::KdfParams;
use holm_platform::fs_store::FsStore;
use holm_platform::lock::{self, InstanceLock, LockError};
use holm_platform::paths;

use crate::messages;
use crate::screens::create::CreateForm;
use crate::screens::unlock::UnlockForm;
use crate::screens::{Screen, VaultView};
use crate::worker::{self, Job, JobKind, Spawner, WorkDone};

/// How often the UI polls a running worker, in case its wake-up repaint is missed.
const WORKER_POLL: Duration = Duration::from_millis(200);

/// Where secrets go when the user copies one. A stub until the clipboard task fills
/// it in; [`NoClipboard`] does nothing.
pub trait SecretClipboard {}

/// A clipboard that never holds anything.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoClipboard;

impl SecretClipboard for NoClipboard {}

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
    /// The clipboard for copied secrets.
    pub clipboard: Box<dyn SecretClipboard>,
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
    /// The clipboard for copied secrets.
    #[expect(dead_code, reason = "the copy buttons use it (Task 5)")]
    clipboard: Box<dyn SecretClipboard>,
    /// Starts the worker: [`worker::spawn`], or a fake in tests.
    spawner: Spawner,
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
            spawner: spawn_worker,
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

    /// Replaces the worker spawner. For tests that need a worker that fails.
    #[doc(hidden)]
    #[must_use]
    pub fn with_spawner(mut self, spawner: Spawner) -> HolmApp {
        self.spawner = spawner;
        self
    }

    /// Per-frame work before drawing: takes the worker's answer when it is there, and
    /// asks for the repaints that keep the screen current without input.
    pub fn tick(&mut self, ctx: &egui::Context) {
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
                if view.revealed() {
                    ctx.request_repaint_after(Duration::from_secs(1));
                }
                None
            }
            Screen::Create(_) | Screen::Fatal(_) => None,
        };
        match polled {
            None => {}
            Some(Ok(done)) => self.finish(done),
            Some(Err(TryRecvError::Empty)) => ctx.request_repaint_after(WORKER_POLL),
            // The worker ended without an answer: it took the session with it. The
            // vault file is untouched (create writes only after Argon2 succeeds).
            Some(Err(TryRecvError::Disconnected)) => {
                self.screen = Screen::Fatal(messages::WORKER_LOST);
            }
        }
    }

    /// Draws the current screen, and starts the worker when a form submits.
    pub fn show(&mut self, ui: &mut egui::Ui) {
        let throttle = self.throttle_status();
        let kdf = self.kdf;
        let now = self.ui_clock.monotonic();
        let screen = &mut self.screen;
        let session = self.session.as_ref();
        if let Screen::Vault(view) = screen {
            let job = view.show(ui, session, now);
            if let Some(job) = job {
                self.start(ui.ctx(), job);
                ui.ctx().request_discard("the screen changed");
            }
            return;
        }
        let job = egui::CentralPanel::default()
            .show(ui, |ui| match screen {
                Screen::Create(form) => form.show(ui).map(|password| Job::Create(password, kdf)),
                Screen::Unlock(form) => form.show(ui, &throttle).map(Job::Unlock),
                Screen::Working { job, .. } => {
                    ui.heading(match job {
                        JobKind::Create => "Creating your vault. This takes a moment.",
                        JobKind::Unlock => "Unlocking. This takes a moment.",
                        JobKind::Add | JobKind::Update | JobKind::Save => "Saving.",
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
        } = done;
        let keep = match core::mem::replace(&mut self.screen, Screen::Fatal(messages::WORKER_LOST))
        {
            Screen::Working { keep, .. } => keep,
            _ => None,
        };
        if matches!(kind, JobKind::Add | JobKind::Update | JobKind::Save) {
            let mut view = keep.unwrap_or_else(VaultView::new);
            if result.is_ok() {
                session.note_activity();
            }
            view.on_done(kind, &result, added, &session);
            self.screen = Screen::Vault(view);
            self.session = Some(session);
            return;
        }
        self.screen = match (kind, result) {
            (_, Ok(())) => {
                session.note_activity();
                Screen::Vault(VaultView::new())
            }
            // Another process made the vault after this app showed Create.
            (JobKind::Create, Err(CoreError::VaultExists)) => Screen::Unlock(UnlockForm::new()),
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
            (JobKind::Add | JobKind::Update | JobKind::Save, Err(_)) => {
                Screen::Fatal(messages::WORKER_LOST)
            }
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

impl eframe::App for HolmApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.tick(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
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
