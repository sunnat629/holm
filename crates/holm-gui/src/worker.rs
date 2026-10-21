//! The worker thread: runs Argon2 (create or unlock) off the UI thread.
//!
//! The session moves into one short-lived thread named `holm-work` and comes back in a
//! [`WorkDone`] over a channel, so it always has exactly one owner and no lock is
//! needed. The master password moves in too and is dropped (wiped) on the worker
//! before the answer is sent. If the thread dies without answering (a panic), the
//! sender drops with it, and the UI sees a disconnected channel.

use core::fmt;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use holm_core::envelope::VaultError;
use holm_core::error::CoreError;
use holm_core::import::{ImportBatch, ImportPreview, ImportReport};
use holm_core::item::{ItemData, ItemId, ItemInput};
use holm_core::session::Session;
use holm_core::text::SecretText;
use holm_crypto::MasterPassword;
use holm_crypto::kdf::KdfParams;
use holm_platform::fs_store::FsStore;
use holm_platform::transfer::{self, TransferError};

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
    /// Read and parse the import file at this path, and preview it. Nothing is added.
    PreviewImport(PathBuf),
    /// Add the rows of a previewed batch and save.
    Import(Box<ImportBatch>),
    /// Check the password, then write the plaintext CSV to a new private file.
    Export {
        /// Where to write. It must not exist.
        path: PathBuf,
        /// The master password, checked on the worker and wiped there.
        password: MasterPassword,
    },
    /// Write an encrypted backup of the vault to a new file.
    Backup {
        /// Where to write. It must not exist.
        path: PathBuf,
    },
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
            Job::PreviewImport(_) => JobKind::PreviewImport,
            Job::Import(_) => JobKind::Import,
            Job::Export { .. } => JobKind::Export,
            Job::Backup { .. } => JobKind::Backup,
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
            Job::PreviewImport(_) | Job::Import(_) => {
                write!(f, "Job::{:?}(<file hidden>)", self.kind())
            }
            Job::Export { .. } => write!(f, "Job::Export(<path and password hidden>)"),
            Job::Backup { .. } => write!(f, "Job::Backup(<path hidden>)"),
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
    /// Reading an import file.
    PreviewImport,
    /// Adding the rows of an import.
    Import,
    /// Writing the export file.
    Export,
    /// Writing the encrypted backup file.
    Backup,
}

impl JobKind {
    /// True for the import and export jobs. A failure there is shown on the screen and
    /// never locks the vault.
    #[must_use]
    pub fn is_transfer(self) -> bool {
        matches!(
            self,
            JobKind::PreviewImport | JobKind::Import | JobKind::Export | JobKind::Backup
        )
    }
}

/// How an import or export went. `Debug` shows counts only.
pub enum TransferResult {
    /// The file was read. The batch waits for the user's go-ahead.
    Previewed(Box<ImportBatch>, ImportPreview),
    /// The rows were added.
    Imported(ImportReport),
    /// The export file was written.
    Exported,
    /// The encrypted backup file was written.
    BackedUp,
    /// It did not happen.
    Failed(TransferError),
}

impl fmt::Debug for TransferResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferResult::Previewed(..) => write!(f, "Previewed"),
            TransferResult::Imported(r) => write!(f, "Imported({})", r.imported),
            TransferResult::Exported => write!(f, "Exported"),
            TransferResult::BackedUp => write!(f, "BackedUp"),
            TransferResult::Failed(e) => write!(f, "Failed({e:?})"),
        }
    }
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
    /// The input of an add or update that failed with `TooLargeToSave`, handed back so
    /// the form can be rebuilt. Always `None` otherwise. Wipes itself on drop.
    pub returned: Option<ItemInput>,
    /// The outcome of an import or export job. `None` for every other kind.
    pub transfer: Option<TransferResult>,
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

/// Runs `job` on `session` in a new thread named `holm-work`, and returns the channel
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
        .name("holm-work".to_owned())
        .spawn(move || {
            // Declared first, so it drops last: `wake` runs after `tx` is gone, on
            // the normal path and when a panic unwinds this thread.
            let _wake = WakeOnDrop(wake);
            let tx = tx;
            let mut session = session;
            let kind = job.kind();
            let mut added = None;
            let mut returned = None;
            let mut transfer = None;
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
                Job::Add(input) => {
                    let backup = backup_login(&input);
                    let result = session.add_item(input).map(|id| added = Some(id));
                    keep_on_too_large(&result, backup, &mut returned);
                    result
                }
                Job::Update(id, input) => {
                    let backup = backup_login(&input);
                    let result = session.update_item(id, input);
                    keep_on_too_large(&result, backup, &mut returned);
                    result
                }
                Job::Save => session.save(),
                Job::PreviewImport(path) => {
                    transfer = Some(preview_file(&session, &path));
                    Ok(())
                }
                Job::Import(batch) => {
                    transfer = Some(match session.import(*batch) {
                        Ok(report) => TransferResult::Imported(report),
                        Err(e) => TransferResult::Failed(TransferError::Core(e)),
                    });
                    Ok(())
                }
                Job::Export { path, password } => {
                    transfer = Some(
                        match transfer::export_plain(&mut session, &password, &path) {
                            Ok(_) => TransferResult::Exported,
                            Err(e) => TransferResult::Failed(e),
                        },
                    );
                    drop(password);
                    Ok(())
                }
                Job::Backup { path } => {
                    transfer = Some(match transfer::export_backup(&mut session, &path) {
                        Ok(()) => TransferResult::BackedUp,
                        Err(e) => TransferResult::Failed(e),
                    });
                    Ok(())
                }
            };
            // A send fails only if the app is gone; the session then drops here,
            // which wipes an unlocked vault.
            let _ = tx.send(WorkDone {
                session,
                kind,
                result,
                added,
                returned,
                transfer,
            });
        });
    // On a spawn error the closure, and with it `tx`, is already dropped.
    drop(started);
    rx
}

/// Reads and parses the file through the shared flow, then previews it.
fn preview_file(session: &Session<FsStore>, path: &std::path::Path) -> TransferResult {
    let batch = match transfer::read_import(path, None) {
        Ok(b) => b,
        Err(e) => return TransferResult::Failed(e),
    };
    match session.preview_import(&batch) {
        Ok(preview) => TransferResult::Previewed(Box::new(batch), preview),
        Err(e) => TransferResult::Failed(TransferError::Core(e)),
    }
}

/// A zeroizing copy of a login input, so it survives core consuming the original.
/// `None` for other item kinds (the GUI only builds logins).
fn backup_login(input: &ItemInput) -> Option<ItemInput> {
    let ItemData::Login {
        username,
        password,
        urls,
        notes,
    } = &input.data
    else {
        return None;
    };
    Some(ItemInput {
        title: input.title.clone(),
        category: input.category,
        favourite: input.favourite,
        data: ItemData::Login {
            username: username.clone(),
            password: SecretText::new(password.expose().to_owned()),
            urls: urls.clone(),
            notes: SecretText::new(notes.expose().to_owned()),
        },
    })
}

/// Hands the backup back only when the change was undone for being too large. In every
/// other case it drops here, and so wipes.
fn keep_on_too_large<T>(
    result: &Result<T, CoreError>,
    backup: Option<ItemInput>,
    returned: &mut Option<ItemInput>,
) {
    if matches!(result, Err(CoreError::Vault(VaultError::TooLargeToSave))) {
        *returned = backup;
    }
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
