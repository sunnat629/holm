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
}

impl Job {
    /// Which kind of work this is.
    #[must_use]
    pub fn kind(&self) -> JobKind {
        match self {
            Job::Create(..) => JobKind::Create,
            Job::Unlock(_) => JobKind::Unlock,
        }
    }
}

impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Job::{:?}(<password hidden>)", self.kind())
    }
}

/// The kind of a [`Job`], without its password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobKind {
    /// Creating a vault.
    Create,
    /// Unlocking a vault.
    Unlock,
}

/// The worker's answer: the session handed back, and how the work went.
pub struct WorkDone {
    /// The session, unlocked on success.
    pub session: Session<FsStore>,
    /// What the work was.
    pub kind: JobKind,
    /// How it went.
    pub result: Result<(), CoreError>,
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
            };
            // A send fails only if the app is gone; the session then drops here,
            // which wipes an unlocked vault.
            let _ = tx.send(WorkDone {
                session,
                kind,
                result,
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
}
