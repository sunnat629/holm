//! The worker thread: runs Argon2 (create or unlock) off the UI thread.
//!
//! The session moves into one short-lived thread named `holm-kdf` and comes back in a
//! [`WorkDone`] over a channel, so it always has exactly one owner and no lock is
//! needed. The master password moves in too and is dropped (wiped) on the worker
//! before the answer is sent. If the thread dies without answering (a panic), the
//! sender drops with it, and the UI sees a disconnected channel.

use core::fmt;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use holm_core::error::CoreError;
use holm_core::item::{ItemId, ItemInput};
use holm_core::session::Session;
use holm_crypto::MasterPassword;
use holm_crypto::kdf::KdfParams;
use holm_platform::fs_store::FsStore;

/// One piece of work for the worker. `Debug` names the kind only.
pub enum Job {
    /// Create a new vault with this password and these Argon2 costs.
    Create(MasterPassword, KdfParams),
    /// Unlock the vault with this password.
    Unlock(MasterPassword),
    /// Add this item and save. The input moves in and is wiped on the worker.
    Add(ItemInput),
    /// Replace this item's fields and save.
    Update(ItemId, ItemInput),
    /// Write the unsaved changes to disk.
    Save,
}

impl Job {
    /// Which kind of work this is.
    #[must_use]
    pub fn kind(&self) -> JobKind {
        match self {
            Job::Create(..) => JobKind::Create,
            Job::Unlock(_) => JobKind::Unlock,
            Job::Add(_) => JobKind::Add,
            Job::Update(..) => JobKind::Update,
            Job::Save => JobKind::Save,
        }
    }
}

impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Job::Create(..) | Job::Unlock(_) => {
                write!(f, "Job::{:?}(<password hidden>)", self.kind())
            }
            Job::Add(_) | Job::Update(..) => write!(f, "Job::{:?}(<item hidden>)", self.kind()),
            Job::Save => write!(f, "Job::Save"),
        }
    }
}

/// The kind of a [`Job`], without its password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobKind {
    /// Creating a vault.
    Create,
    /// Unlocking a vault.
    Unlock,
    /// Adding an item.
    Add,
    /// Updating an item.
    Update,
    /// Saving unsaved changes.
    Save,
}

/// The worker's answer: the session handed back, and how the work went.
pub struct WorkDone {
    /// The session, unlocked on success.
    pub session: Session<FsStore>,
    /// What the work was.
    pub kind: JobKind,
    /// How it went.
    pub result: Result<(), CoreError>,
    /// The id of the item an add made. Present for an add that returned an id.
    pub added: Option<ItemId>,
}

impl fmt::Debug for WorkDone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkDone")
            .field("kind", &self.kind)
            .field("ok", &self.result.is_ok())
            .finish_non_exhaustive()
    }
}

/// How the app starts a job: [`spawn`] in the app, a fake in tests.
pub type Spawner = fn(Session<FsStore>, Job, Box<dyn Fn() + Send>) -> Receiver<WorkDone>;

/// Runs `job` on `session` in a new thread named `holm-kdf`, and returns the channel
/// its [`WorkDone`] arrives on.
///
/// The password is dropped (and so wiped) on the worker before the answer is sent.
/// `wake` is called after the send, and also when the thread unwinds from a panic, so
/// the UI repaints and sees the answer or the disconnected channel. If the thread
/// cannot be started, the job and the session are dropped and the channel is already
/// disconnected.
pub fn spawn(
    session: Session<FsStore>,
    job: Job,
    wake: impl Fn() + Send + 'static,
) -> Receiver<WorkDone> {
    let (tx, rx) = mpsc::channel();
    let started = thread::Builder::new()
        .name("holm-kdf".to_owned())
        .spawn(move || {
            // Declared first, so it drops last: `wake` runs after `tx` is gone, on
            // the normal path and when a panic unwinds this thread.
            let _wake = WakeOnDrop(wake);
            let tx = tx;
            let mut session = session;
            let kind = job.kind();
            let mut added = None;
            let result = match job {
                Job::Create(password, params) => {
                    let result = session.create(&password, &params);
                    drop(password);
                    result
                }
                Job::Unlock(password) => {
                    let result = session.unlock(&password);
                    drop(password);
                    result
                }
                Job::Add(input) => session.add_item(input).map(|id| added = Some(id)),
                Job::Update(id, input) => session.update_item(id, input),
                Job::Save => session.save(),
            };
            // A send fails only if the app is gone; the session then drops here,
            // which wipes an unlocked vault.
            let _ = tx.send(WorkDone {
                session,
                kind,
                result,
                added,
            });
        });
    // On a spawn error the closure, and with it `tx`, is already dropped.
    drop(started);
    rx
}

/// Calls the wake function when dropped.
struct WakeOnDrop<F: Fn()>(F);

impl<F: Fn()> Drop for WakeOnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use holm_core::clock::SystemClock;

    #[test]
    fn job_debug_hides_the_password() {
        let job = Job::Unlock(MasterPassword::new("EXAMPLE-pw".to_owned()));
        let shown = format!("{job:?}");
        assert_eq!(shown, "Job::Unlock(<password hidden>)");
        let job = Job::Create(
            MasterPassword::new("EXAMPLE-pw".to_owned()),
            KdfParams::FLOOR,
        );
        assert_eq!(format!("{job:?}"), "Job::Create(<password hidden>)");
    }

    #[test]
    fn worker_hands_the_session_back_and_wakes() {
        let dir = tempfile::tempdir().unwrap();
        let session = Session::new(
            FsStore::new(dir.path().join("holm.vault")),
            Box::new(SystemClock::new()),
        );
        let wakes = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&wakes);
        let rx = spawn(
            session,
            Job::Unlock(MasterPassword::new("EXAMPLE-pw".to_owned())),
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
            },
        );
        let done = rx.recv().unwrap();
        assert_eq!(done.kind, JobKind::Unlock);
        // No file: refused before any Argon2 work.
        assert_eq!(done.result, Err(CoreError::NoVault));
        assert!(!done.session.is_unlocked());
        assert_eq!(
            format!("{done:?}"),
            "WorkDone { kind: Unlock, ok: false, .. }"
        );
        // The thread is gone after the wake, so the channel disconnects.
        assert!(rx.recv().is_err());
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
    }
    fn login(title: &str) -> ItemInput {
        use holm_core::item::ItemData;
        use holm_core::text::{SecretText, Text};
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

    fn run(session: Session<FsStore>, job: Job) -> WorkDone {
        spawn(session, job, || {}).recv().unwrap()
    }

    #[test]
    fn add_update_and_save_jobs_run_on_the_worker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Holm").join("holm.vault");
        holm_platform::paths::ensure_vault_dir(&path).unwrap();
        let mut session = Session::new(FsStore::new(path), Box::new(SystemClock::new()));
        let password = MasterPassword::new("correct-Horse-battery-staple-EXAMPLE-9".to_owned());
        session.create(&password, &KdfParams::FLOOR).unwrap();

        let done = run(session, Job::Add(login("First")));
        assert_eq!(done.kind, JobKind::Add);
        assert_eq!(done.result, Ok(()));
        let id = done.added.expect("an add returns the new id");
        assert!(!done.session.is_dirty(), "an add saves");

        let done = run(done.session, Job::Update(id, login("Renamed")));
        assert_eq!(done.kind, JobKind::Update);
        assert_eq!(done.result, Ok(()));
        assert_eq!(done.added, None);
        assert_eq!(done.session.item(id).unwrap().title(), "Renamed");

        let done = run(done.session, Job::Save);
        assert_eq!(done.kind, JobKind::Save);
        assert_eq!(done.result, Ok(()));
        assert_eq!(
            format!("{:?}", Job::Add(login("Secret title"))),
            "Job::Add(<item hidden>)"
        );
    }
}
