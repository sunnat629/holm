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
use holm_core::fields::{CustomField, FieldValue, RecoveryCode, try_field};
use holm_core::import::{ImportBatch, ImportPreview, ImportReport};
use holm_core::item::{ItemData, ItemId, ItemInput};
use holm_core::rules::FieldError;
use holm_core::session::Session;
use holm_core::text::{SecretText, Text};
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
    /// Replace this item's fields, custom fields included, and save.
    Update(ItemId, ItemInput),
    /// Replace only this item's custom fields, and save. The fields move in and are
    /// wiped on the worker.
    SetFields(ItemId, Vec<CustomField>),
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
    /// Check the password, then hand back a copy of this recovery phrase.
    RevealPhrase {
        /// The recovery phrase item.
        id: ItemId,
        /// The master password, checked on the worker and wiped there.
        password: MasterPassword,
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
            Job::Update(..) | Job::SetFields(..) => JobKind::Update,
            Job::Save => JobKind::Save,
            Job::PreviewImport(_) => JobKind::PreviewImport,
            Job::Import(_) => JobKind::Import,
            Job::Export { .. } => JobKind::Export,
            Job::Backup { .. } => JobKind::Backup,
            Job::RevealPhrase { .. } => JobKind::RevealPhrase,
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
            Job::SetFields(..) => write!(f, "Job::SetFields(<item hidden>)"),
            Job::Save => write!(f, "Job::Save"),
            Job::PreviewImport(_) | Job::Import(_) => {
                write!(f, "Job::{:?}(<file hidden>)", self.kind())
            }
            Job::Export { .. } => write!(f, "Job::Export(<path and password hidden>)"),
            Job::Backup { .. } => write!(f, "Job::Backup(<path hidden>)"),
            Job::RevealPhrase { .. } => write!(f, "Job::RevealPhrase(<password hidden>)"),
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
    /// Checking the password to show a recovery phrase.
    RevealPhrase,
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
    /// The recovery phrase a successful reveal hands back. Wipes itself on drop.
    /// `None` for every other kind and for a failed reveal. Never in `Debug`.
    pub phrase: Option<SecretText>,
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
            let mut phrase = None;
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
                Job::Update(id, mut input) => {
                    // The backup is taken first, so it holds the custom fields too.
                    let backup = backup_login(&input);
                    // `update_item` ignores `input.fields`: they are set afterwards.
                    let fields = core::mem::take(&mut input.fields);
                    let result = session.update_item(id, input).and_then(|()| {
                        session.set_custom_fields(id, fields)?;
                        if session.is_dirty() {
                            session.save()
                        } else {
                            Ok(())
                        }
                    });
                    keep_on_too_large(&result, backup, &mut returned);
                    result
                }
                Job::SetFields(id, fields) => {
                    session.set_custom_fields(id, fields).and_then(|()| {
                        if session.is_dirty() {
                            session.save()
                        } else {
                            Ok(())
                        }
                    })
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
                Job::RevealPhrase { id, password } => {
                    // A wrong password counts toward the throttle inside the core.
                    let result = session
                        .reveal_phrase(id, &password)
                        .map(|words| phrase = Some(SecretText::new(words.to_owned())));
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
                added,
                returned,
                transfer,
                phrase,
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

/// A zeroizing copy of a login input, custom fields included, so it survives core
/// consuming the original. `None` for other item kinds (the GUI only builds logins), and
/// when a custom field breaks a field rule (core then refuses the input before any
/// `TooLargeToSave`, so the backup would never be handed back).
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
    let fields = input
        .fields
        .iter()
        .map(copy_field)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    Some(ItemInput {
        fields,
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

/// A wiping copy of one custom field. `CustomField` has no `Clone`, so the copy is
/// rebuilt through `try_field`; a secret goes straight into a new `SecretText`.
fn copy_field(field: &CustomField) -> Result<CustomField, FieldError> {
    copy_field_flipping(field, None)
}

/// [`copy_field`], with the `used` flag of the recovery code at `flip` inverted. `None`,
/// or a field that holds no such code, gives an exact copy.
pub(crate) fn copy_field_flipping(
    field: &CustomField,
    flip: Option<usize>,
) -> Result<CustomField, FieldError> {
    let value = match field.value() {
        FieldValue::Text(text) => FieldValue::Text(text.clone()),
        FieldValue::Secret(secret) => {
            FieldValue::Secret(SecretText::new(secret.expose().to_owned()))
        }
        FieldValue::MultilineSecret(secret) => {
            FieldValue::MultilineSecret(SecretText::new(secret.expose().to_owned()))
        }
        FieldValue::Date(date) => FieldValue::Date(*date),
        FieldValue::RecoveryCodes(codes) => FieldValue::RecoveryCodes(
            codes
                .iter()
                .enumerate()
                .map(|(i, code)| {
                    RecoveryCode::new(
                        SecretText::new(code.code().expose().to_owned()),
                        code.used() ^ (flip == Some(i)),
                    )
                })
                .collect(),
        ),
    };
    try_field(Text::new(field.label().to_owned()), value, field.expiry())
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
        let job = Job::RevealPhrase {
            id: ItemId::random().unwrap(),
            password: MasterPassword::new("EXAMPLE-pw".to_owned()),
        };
        assert_eq!(format!("{job:?}"), "Job::RevealPhrase(<password hidden>)");
        assert!(!job.kind().is_transfer());
        let job = Job::SetFields(ItemId::random().unwrap(), Vec::new());
        assert_eq!(format!("{job:?}"), "Job::SetFields(<item hidden>)");
        assert_eq!(job.kind(), JobKind::Update);
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
            fields: Vec::new(),
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

    #[test]
    fn backup_login_keeps_custom_fields() {
        use holm_core::fields::{FieldValue, parse_date, try_field};
        use holm_core::text::{SecretText, Text};

        let mut input = login("With fields");
        input.fields = vec![
            try_field(
                Text::new("PIN".to_owned()),
                FieldValue::Secret(SecretText::new("EXAMPLE-field-secret".to_owned())),
                parse_date("2026-11-05"),
            )
            .unwrap(),
            try_field(
                Text::new("SSH private key".to_owned()),
                FieldValue::MultilineSecret(SecretText::new(
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nEXAMPLE\n".to_owned(),
                )),
                None,
            )
            .unwrap(),
            try_field(
                Text::new("Account".to_owned()),
                FieldValue::Text(Text::new("public-note-EXAMPLE".to_owned())),
                None,
            )
            .unwrap(),
            try_field(
                Text::new("Expiry".to_owned()),
                FieldValue::Date(parse_date("2027-01-31").unwrap()),
                None,
            )
            .unwrap(),
        ];

        let backup = backup_login(&input).expect("a login has a backup");
        assert_eq!(backup.fields.len(), input.fields.len());
        for (copy, original) in backup.fields.iter().zip(&input.fields) {
            assert_eq!(copy.label(), original.label());
            assert_eq!(copy.kind(), original.kind());
            assert_eq!(copy.expiry(), original.expiry());
            let same = match (copy.value(), original.value()) {
                (FieldValue::Text(a), FieldValue::Text(b)) => a.as_str() == b.as_str(),
                (FieldValue::Secret(a), FieldValue::Secret(b))
                | (FieldValue::MultilineSecret(a), FieldValue::MultilineSecret(b)) => {
                    a.expose() == b.expose()
                }
                (FieldValue::Date(a), FieldValue::Date(b)) => a == b,
                _ => false,
            };
            assert!(same, "field {} changed", copy.label());
        }
        assert!(!format!("{:?}", backup.fields).contains("EXAMPLE"));
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

    #[test]
    fn update_job_keeps_and_sets_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Holm").join("holm.vault");
        holm_platform::paths::ensure_vault_dir(&path).unwrap();
        let mut session = Session::new(FsStore::new(path), Box::new(SystemClock::new()));
        let password = MasterPassword::new("correct-Horse-battery-staple-EXAMPLE-9".to_owned());
        session.create(&password, &KdfParams::FLOOR).unwrap();

        let done = run(session, Job::Add(login("Server")));
        let id = done.added.expect("an add returns the new id");

        // An update sets new custom fields.
        let mut input = login("Server");
        input.fields = vec![
            try_field(
                Text::new("PIN".to_owned()),
                FieldValue::Secret(SecretText::new("EXAMPLE-field-secret".to_owned())),
                None,
            )
            .unwrap(),
        ];
        let done = run(done.session, Job::Update(id, input));
        assert_eq!(done.kind, JobKind::Update);
        assert_eq!(done.result, Ok(()));
        assert!(done.returned.is_none());
        assert!(!done.session.is_dirty(), "the fields are saved");
        {
            let item = done.session.item(id).unwrap();
            assert_eq!(item.fields().len(), 1);
            assert_eq!(item.fields()[0].label(), "PIN");
            assert!(matches!(
                item.fields()[0].value(),
                FieldValue::Secret(s) if s.expose() == "EXAMPLE-field-secret"
            ));
        }

        // An edit that sends the stored fields back keeps them.
        let kept = done
            .session
            .item(id)
            .unwrap()
            .fields()
            .iter()
            .map(|f| copy_field(f).unwrap())
            .collect::<Vec<_>>();
        let mut input = login("Renamed");
        input.fields = kept;
        let done = run(done.session, Job::Update(id, input));
        assert_eq!(done.result, Ok(()));
        assert!(!done.session.is_dirty());
        let item = done.session.item(id).unwrap();
        assert_eq!(item.title(), "Renamed");
        assert_eq!(item.fields().len(), 1, "an edit never drops a stored field");
        assert!(matches!(
            item.fields()[0].value(),
            FieldValue::Secret(s) if s.expose() == "EXAMPLE-field-secret"
        ));
    }
}
