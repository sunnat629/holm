//! Every error and status line the app's screens show.
//!
//! Each line is fixed text written here, never a path, a field value or a library
//! error's `Display`. The mapping functions take a core error and return one of these
//! constants, so the screen shows the same words for the same problem every time.
//! Pure Rust, no egui: the tables are tested on every OS.

use std::io::ErrorKind;
use std::time::Duration;

use holm_core::body::BodyError;
use holm_core::envelope::VaultError;
use holm_core::error::CoreError;
use holm_core::import::ImportError;
use holm_core::rules::{Field, FieldError};
use holm_core::settings::{CLIPBOARD_MAX_SECS, CLIPBOARD_MIN_SECS};
use holm_core::store::StoreError;
use holm_core::throttle::ThrottleStatus;

/// A wrong password, or a vault file that was changed or damaged. The two cannot be
/// told apart, so one line covers both.
pub const WRONG_PASSWORD: &str = "That password didn't open this vault. Either the password is wrong, or the file was changed or damaged.";
/// The memory for the key derivation could not be reserved.
pub const NOT_ENOUGH_MEMORY: &str =
    "Holm didn't have enough memory for this. Close some apps and try again.";
/// The vault's key-derivation costs are outside Holm's policy.
pub const KDF_POLICY: &str =
    "This vault's security settings are outside what Holm accepts, so Holm won't open it.";
/// The file is not a Holm vault, or it is damaged.
pub const NOT_A_VAULT: &str = "This file isn't a Holm vault, or it is damaged.";
/// The vault body was written by a newer Holm.
pub const NEWER_VAULT: &str = "This vault was made by a newer Holm. Update Holm to open it.";
/// There is no vault file at the path.
pub const NO_VAULT: &str = "Holm found no vault here.";
/// The vault file could not be read.
pub const READ_FAILED: &str = "Holm couldn't read the vault file.";
/// Any other unlock failure.
pub const UNLOCK_FAILED: &str = "Holm couldn't open this vault.";
/// The core refused an unlock because of the throttle. The screen shows the live
/// [`throttle_line`] instead whenever it can.
pub const TOO_MANY_TRIES: &str = "Too many tries. Wait a moment and try again.";

/// The vault folder (or a write into it) is open to other users.
pub const DIR_PERMISSIONS: &str = "Holm can't save here because other users can change this folder. Fix the folder's permissions and try again.";
/// The vault folder could not be made or used, for any other reason.
pub const DIR_ERROR: &str = "Holm couldn't use the folder for its vault. Check that the folder exists and is a normal folder.";
/// Another Holm holds the vault folder's lock.
pub const ALREADY_OPEN: &str = "Holm is already open. Close the other window first.";
/// The worker thread ended without an answer (it panicked).
pub const WORKER_LOST: &str = "Something went wrong while Holm was working. The vault file was not changed. Quit Holm and open it again.";

/// The two password fields differ (shown on submit only).
pub const PASSWORDS_DIFFER: &str = "The two passwords don't match.";
/// The master password is below the strength policy.
pub const WEAK_PASSWORD: &str = "This master password is too easy to guess. Choose a stronger one.";
/// The "I understand" box is not ticked.
pub const TICK_TO_CONTINUE: &str =
    "Tick the box to confirm that you understand Holm can't recover your vault.";
/// A vault already exists at the path. The app switches to the unlock screen instead
/// of showing this, but the table still maps the error to fixed text.
pub const VAULT_EXISTS: &str = "A vault already exists here. Unlock it instead.";
/// The new vault file could not be written.
pub const SAVE_FAILED: &str = "Holm couldn't save the new vault. Try again.";
/// The create failed after the file was written (the folder sync failed), so the vault
/// may already exist and the password just chosen may open it.
pub const CREATE_MAYBE_SAVED: &str =
    "Holm may have saved your vault anyway. Try to unlock it with the password you just chose.";
/// Any other create failure.
pub const CREATE_FAILED: &str = "Holm couldn't create the vault. Try again.";

/// The title is empty.
pub const TITLE_EMPTY: &str = "Add a title.";
/// A field is longer than allowed.
pub const FIELD_TOO_LONG: &str = "One of the fields is too long. Shorten it.";
/// A field has spaces at its ends or hidden characters.
pub const FIELD_FORBIDDEN: &str = "Remove spaces at the ends and hidden characters.";
/// More web addresses than a login may hold.
pub const TOO_MANY_URLS: &str = "This login has too many web addresses.";
/// A field that must not be empty is empty.
pub const FIELD_EMPTY: &str = "Fill in the field that is empty.";
/// A field holds a reserved word.
pub const FIELD_RESERVED: &str = "That name is reserved. Choose another.";
/// The vault would grow past its size limit.
pub const TOO_LARGE_TO_SAVE: &str =
    "The vault is too large to save this change. Nothing was changed.";
/// The change is in memory but not on disk.
pub const NOT_SAVED: &str = "Not saved. The change is open in Holm but is not on disk yet.";
/// The stored password is longer than the edit form can hold.
pub const SECRET_TOO_LONG: &str =
    "This password is too long to edit here, so it is shown read-only.";
/// No login is selected.
pub const SELECT_OR_ADD: &str = "Select a login, or add one.";
/// The line after a copy, naming the vault's clipboard time. `secs` is clamped to the
/// settings range, as the clear itself clamps it.
#[must_use]
pub fn copied_note(secs: u32) -> String {
    let secs = secs.clamp(CLIPBOARD_MIN_SECS, CLIPBOARD_MAX_SECS);
    format!("Copied. Holm clears the clipboard in {secs} seconds.")
}
/// The auto-clear found another app's copy on the clipboard and left it alone.
pub const CLIPBOARD_CHANGED: &str = "The clipboard changed, so Holm left it alone.";
/// The auto-clear ran but the password is still on the clipboard.
pub const CLIPBOARD_NOT_CLEARED: &str =
    "Holm couldn't clear the clipboard. Copy something else to replace it.";
/// The clipboard did not take the password.
pub const COPY_FAILED: &str = "Couldn't copy. Try again.";
/// A paste would not fit the field, so nothing was pasted.
pub const PASTE_TOO_LONG: &str = "That's too long to paste here, so nothing was pasted.";

/// The lock dialog's question, shown when a manual lock finds unsaved changes.
pub const UNSAVED_ON_LOCK: &str =
    "Some changes are not saved yet. Locking now without saving discards them.";

/// No file at the typed path, so nothing was read.
pub const IMPORT_NOT_FOUND: &str = "Holm found no file at that path. Check the path and try again.";
/// The file could not be read.
pub const IMPORT_READ_FAILED: &str = "Holm could not read that file. Nothing was imported.";
/// The file is bigger than the import limit.
pub const IMPORT_TOO_BIG: &str = "That file is too big to import. The limit is 16 MiB.";
/// The file is not text Holm can read.
pub const IMPORT_NOT_TEXT: &str =
    "That file is not plain text in UTF-8, so Holm cannot read it. Nothing was imported.";
/// The file holds nothing.
pub const IMPORT_EMPTY: &str = "That file is empty. Nothing was imported.";
/// The file's columns are not ones Holm knows.
pub const IMPORT_COLUMNS: &str =
    "That file's columns are not ones Holm knows how to import. Nothing was imported.";
/// The file has more columns or rows than the import limit.
pub const IMPORT_TOO_MANY: &str =
    "That file has too many columns or rows to import. Nothing was imported.";
/// The file's text is broken.
pub const IMPORT_MALFORMED: &str =
    "That file is damaged or not a CSV or JSON export. Nothing was imported.";
/// The import would not fit, so nothing was added.
pub const IMPORT_NOT_ADDED: &str =
    "These items would not fit in the vault, so nothing was imported.";
/// The import was added in memory, but saving failed.
pub const IMPORT_UNSAVED: &str = "The items were added but could not be saved yet. Select Try again to save them, or lock and import the file again.";
/// The import failed for another reason.
pub const IMPORT_FAILED: &str = "The import did not finish.";
/// The export file already exists, so nothing was written.
pub const EXPORT_EXISTS: &str =
    "A file already exists at that path. Holm never overwrites a file. Pick a new name.";
/// The export file could not be written.
pub const EXPORT_WRITE_FAILED: &str =
    "Holm could not write the file there. Check the folder and try again.";
/// The password typed to confirm the export is wrong.
pub const EXPORT_WRONG_PASSWORD: &str = "That password is wrong, so nothing was exported.";
/// Too many wrong passwords in a row.
pub const EXPORT_THROTTLED: &str = "Too many wrong passwords. Wait a little and try again.";
/// The export failed for another reason.
pub const EXPORT_FAILED: &str = "The export did not finish. No file was written.";

/// Accessibility label of the press-and-hold eye on a password field. It is a button
/// label, not a status line, so it stays out of `ALL` (which holds full sentences).
pub const EYE_LABEL: &str = "Show password while held";

/// Every constant above, for the plain-text test.
#[cfg(test)]
const ALL: [&str; 51] = [
    WRONG_PASSWORD,
    NOT_ENOUGH_MEMORY,
    KDF_POLICY,
    NOT_A_VAULT,
    NEWER_VAULT,
    NO_VAULT,
    READ_FAILED,
    UNLOCK_FAILED,
    TOO_MANY_TRIES,
    DIR_PERMISSIONS,
    DIR_ERROR,
    ALREADY_OPEN,
    WORKER_LOST,
    PASSWORDS_DIFFER,
    WEAK_PASSWORD,
    TICK_TO_CONTINUE,
    VAULT_EXISTS,
    SAVE_FAILED,
    CREATE_MAYBE_SAVED,
    CREATE_FAILED,
    TITLE_EMPTY,
    FIELD_TOO_LONG,
    FIELD_FORBIDDEN,
    TOO_MANY_URLS,
    FIELD_EMPTY,
    FIELD_RESERVED,
    TOO_LARGE_TO_SAVE,
    NOT_SAVED,
    SECRET_TOO_LONG,
    SELECT_OR_ADD,
    CLIPBOARD_CHANGED,
    CLIPBOARD_NOT_CLEARED,
    COPY_FAILED,
    PASTE_TOO_LONG,
    UNSAVED_ON_LOCK,
    IMPORT_NOT_FOUND,
    IMPORT_READ_FAILED,
    IMPORT_TOO_BIG,
    IMPORT_NOT_TEXT,
    IMPORT_EMPTY,
    IMPORT_COLUMNS,
    IMPORT_TOO_MANY,
    IMPORT_MALFORMED,
    IMPORT_NOT_ADDED,
    IMPORT_UNSAVED,
    IMPORT_FAILED,
    EXPORT_EXISTS,
    EXPORT_WRITE_FAILED,
    EXPORT_WRONG_PASSWORD,
    EXPORT_THROTTLED,
    EXPORT_FAILED,
];

/// Why the vault locked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockReason {
    /// The Lock button or Cmd+L.
    Manual,
    /// No activity for the auto-lock time.
    Idle,
    /// The window was minimised.
    Minimised,
}

/// What the unlock screen says about the last lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockNote {
    /// Why the vault locked.
    pub reason: LockReason,
    /// Whether the session had unsaved changes, now discarded.
    pub discarded_unsaved: bool,
}

/// The line the unlock screen shows for an unlock error.
#[must_use]
pub fn unlock_error(e: &CoreError) -> &'static str {
    match e {
        CoreError::WrongPassword | CoreError::Vault(VaultError::WrongPasswordOrCorrupt) => {
            WRONG_PASSWORD
        }
        CoreError::Vault(VaultError::OutOfMemory) => NOT_ENOUGH_MEMORY,
        CoreError::Vault(VaultError::KdfPolicy(_)) => KDF_POLICY,
        CoreError::Vault(VaultError::Format(_) | VaultError::BadPadding)
        | CoreError::Store(StoreError::NotARegularFile) => NOT_A_VAULT,
        CoreError::Body(BodyError::NewerSchema(_)) => NEWER_VAULT,
        CoreError::NoVault => NO_VAULT,
        CoreError::Store(_) => READ_FAILED,
        CoreError::Throttled { .. } => TOO_MANY_TRIES,
        _ => UNLOCK_FAILED,
    }
}

/// The line the create screen shows for a create error, and the start-up text for a
/// vault-folder error from `ensure_vault_dir` (wrapped as [`CoreError::Store`]).
///
/// [`CoreError::VaultExists`] maps to [`VAULT_EXISTS`], but the app never shows it:
/// it switches to the unlock screen instead.
#[must_use]
pub fn create_error(e: &CoreError) -> &'static str {
    match e {
        CoreError::Store(StoreError::Io(ErrorKind::PermissionDenied)) => DIR_PERMISSIONS,
        CoreError::VaultExists => VAULT_EXISTS,
        CoreError::WeakPassword(_) => WEAK_PASSWORD,
        CoreError::Vault(VaultError::OutOfMemory) => NOT_ENOUGH_MEMORY,
        CoreError::Store(_) => SAVE_FAILED,
        _ => CREATE_FAILED,
    }
}

/// The line for a field rule that failed. It names no value.
#[must_use]
pub fn field_error(e: &FieldError) -> &'static str {
    match e {
        FieldError::Empty(Field::Title) => TITLE_EMPTY,
        FieldError::Empty(_) => FIELD_EMPTY,
        FieldError::TooLong(_) => FIELD_TOO_LONG,
        FieldError::ForbiddenChar(_) => FIELD_FORBIDDEN,
        FieldError::TooManyUrls => TOO_MANY_URLS,
        FieldError::Reserved(_) => FIELD_RESERVED,
    }
}

/// The line for a failed item save: the permissions line for a folder open to other
/// users, else [`NOT_SAVED`].
#[must_use]
pub fn save_error(e: &CoreError) -> &'static str {
    match e {
        CoreError::Store(StoreError::Io(ErrorKind::PermissionDenied)) => DIR_PERMISSIONS,
        _ => NOT_SAVED,
    }
}

/// The line for a file that did not parse. Names no row, column or value.
#[must_use]
pub fn import_parse_error(e: &ImportError) -> &'static str {
    match e {
        ImportError::TooLarge => IMPORT_TOO_BIG,
        ImportError::NotUtf8 => IMPORT_NOT_TEXT,
        ImportError::Empty => IMPORT_EMPTY,
        ImportError::UnknownColumns { .. } | ImportError::DuplicateColumn => IMPORT_COLUMNS,
        ImportError::TooManyColumns | ImportError::TooManyRows => IMPORT_TOO_MANY,
        ImportError::Malformed { .. } => IMPORT_MALFORMED,
    }
}

/// The line for a failed import step. Only a vault too big to save, or too many items,
/// leaves nothing added. Any other failure after the rows went in (`items_added`, the
/// session is dirty) leaves them in memory but unsaved, whatever the error type.
#[must_use]
pub fn import_apply_error(e: &CoreError, items_added: bool) -> &'static str {
    match e {
        CoreError::Vault(VaultError::TooLargeToSave) | CoreError::TooManyItems => IMPORT_NOT_ADDED,
        CoreError::Store(_) | CoreError::Vault(_) => IMPORT_UNSAVED,
        _ if items_added => IMPORT_UNSAVED,
        _ => IMPORT_FAILED,
    }
}

/// The line for a failed export.
#[must_use]
pub fn export_error(e: &CoreError) -> &'static str {
    match e {
        CoreError::WrongPassword => EXPORT_WRONG_PASSWORD,
        CoreError::Throttled { .. } => EXPORT_THROTTLED,
        _ => EXPORT_FAILED,
    }
}

/// The start-up text for an error from `ensure_vault_dir`: [`DIR_PERMISSIONS`] for a
/// folder open to other users, else [`DIR_ERROR`].
#[must_use]
pub fn dir_error(e: StoreError) -> &'static str {
    match e {
        StoreError::Io(ErrorKind::PermissionDenied) => DIR_PERMISSIONS,
        _ => DIR_ERROR,
    }
}

/// The throttle line under the unlock form: `None` with no failures, the failure count
/// while no wait is due, and the wait in whole seconds (rounded up) while one is.
/// Numbers only, never anything typed.
#[must_use]
pub fn throttle_line(status: &ThrottleStatus) -> Option<String> {
    if let Some(wait) = status.retry_after {
        return Some(format!(
            "Too many tries. Try again in {} s.",
            ceil_secs(wait)
        ));
    }
    match status.consecutive_failures {
        0 => None,
        1 => Some("1 failed try.".to_owned()),
        n => Some(format!("{n} failed tries.")),
    }
}

/// The line the unlock screen shows after a lock. `auto_lock` is the vault's auto-lock
/// time from its settings, named in the idle line.
#[must_use]
pub fn lock_line(note: &LockNote, auto_lock: Duration) -> String {
    let mut line = match note.reason {
        LockReason::Manual => "Locked.".to_owned(),
        LockReason::Idle => format!("Locked after {} without use.", in_words(auto_lock)),
        LockReason::Minimised => "Locked when the window was minimised.".to_owned(),
    };
    if note.discarded_unsaved {
        line.push_str(" Unsaved changes were discarded.");
    }
    line
}

/// The amber line before an idle lock, with `left` in whole seconds (rounded up).
#[must_use]
pub fn idle_warning(left: Duration) -> String {
    format!("Locking in {} s because of no activity.", ceil_secs(left))
}

/// `d` as "1 minute", "5 minutes" or, when it is not whole minutes, "90 seconds".
fn in_words(d: Duration) -> String {
    let secs = d.as_secs();
    match (secs / 60, secs % 60) {
        (1, 0) => "1 minute".to_owned(),
        (minutes, 0) if minutes > 1 => format!("{minutes} minutes"),
        _ if secs == 1 => "1 second".to_owned(),
        _ => format!("{secs} seconds"),
    }
}

/// `wait` in whole seconds, rounded up, and at least 1 (a wait is only shown while
/// one is due).
fn ceil_secs(wait: Duration) -> u64 {
    let secs = wait
        .as_secs()
        .saturating_add(u64::from(wait.subsec_nanos() > 0));
    secs.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use holm_core::format::FormatError;
    use holm_crypto::error::KdfParamsError;

    fn status(failures: u32, wait_ms: Option<u64>) -> ThrottleStatus {
        ThrottleStatus {
            consecutive_failures: failures,
            retry_after: wait_ms.map(Duration::from_millis),
        }
    }

    #[test]
    fn unlock_error_table() {
        let table: [(CoreError, &str); 13] = [
            (CoreError::WrongPassword, WRONG_PASSWORD),
            (
                CoreError::Vault(VaultError::WrongPasswordOrCorrupt),
                WRONG_PASSWORD,
            ),
            (CoreError::Vault(VaultError::OutOfMemory), NOT_ENOUGH_MEMORY),
            (
                CoreError::Vault(VaultError::KdfPolicy(KdfParamsError::BelowFloor)),
                KDF_POLICY,
            ),
            (
                CoreError::Vault(VaultError::Format(FormatError::BadMagic)),
                NOT_A_VAULT,
            ),
            (CoreError::Vault(VaultError::BadPadding), NOT_A_VAULT),
            (CoreError::Body(BodyError::NewerSchema(9)), NEWER_VAULT),
            (CoreError::NoVault, NO_VAULT),
            (CoreError::Store(StoreError::NotARegularFile), NOT_A_VAULT),
            (CoreError::Store(StoreError::TooLarge), READ_FAILED),
            (
                CoreError::Store(StoreError::Io(ErrorKind::PermissionDenied)),
                READ_FAILED,
            ),
            (CoreError::Body(BodyError::Malformed), UNLOCK_FAILED),
            (
                CoreError::Throttled {
                    retry_after_secs: 4,
                },
                TOO_MANY_TRIES,
            ),
        ];
        for (error, line) in &table {
            assert_eq!(unlock_error(error), *line, "{error:?}");
        }
        assert_eq!(
            unlock_error(&CoreError::Vault(VaultError::Crypto)),
            UNLOCK_FAILED
        );
    }

    #[test]
    fn create_error_table() {
        let denied = StoreError::Io(ErrorKind::PermissionDenied);
        assert_eq!(create_error(&CoreError::Store(denied)), DIR_PERMISSIONS);
        assert_eq!(create_error(&CoreError::VaultExists), VAULT_EXISTS);
        assert_eq!(
            create_error(&CoreError::Store(StoreError::Io(ErrorKind::Other))),
            SAVE_FAILED
        );
        assert_eq!(
            create_error(&CoreError::Vault(VaultError::OutOfMemory)),
            NOT_ENOUGH_MEMORY
        );
        let weak = holm_core::strength::StrengthVerdict {
            score: 1,
            chars: 12,
            acceptable: false,
        };
        assert_eq!(create_error(&CoreError::WeakPassword(weak)), WEAK_PASSWORD);
        assert_eq!(
            create_error(&CoreError::Vault(VaultError::Crypto)),
            CREATE_FAILED
        );

        assert_eq!(dir_error(denied), DIR_PERMISSIONS);
        assert_eq!(dir_error(StoreError::NotARegularFile), DIR_ERROR);
        assert_eq!(dir_error(StoreError::Io(ErrorKind::NotFound)), DIR_ERROR);
    }

    #[test]
    fn field_and_save_error_tables() {
        assert_eq!(field_error(&FieldError::Empty(Field::Title)), TITLE_EMPTY);
        assert_eq!(field_error(&FieldError::Empty(Field::Url)), FIELD_EMPTY);
        assert_eq!(
            field_error(&FieldError::TooLong(Field::Notes)),
            FIELD_TOO_LONG
        );
        assert_eq!(
            field_error(&FieldError::ForbiddenChar(Field::Url)),
            FIELD_FORBIDDEN
        );
        assert_eq!(field_error(&FieldError::TooManyUrls), TOO_MANY_URLS);
        assert_eq!(
            field_error(&FieldError::Reserved(Field::Title)),
            FIELD_RESERVED
        );
        let denied = CoreError::Store(StoreError::Io(ErrorKind::PermissionDenied));
        assert_eq!(save_error(&denied), DIR_PERMISSIONS);
        assert_eq!(save_error(&CoreError::Locked), NOT_SAVED);
        assert_eq!(import_parse_error(&ImportError::Empty), IMPORT_EMPTY);
        assert_eq!(
            import_apply_error(&CoreError::TooManyItems, false),
            IMPORT_NOT_ADDED
        );
        let body = CoreError::Body(BodyError::Malformed);
        assert_eq!(import_apply_error(&body, true), IMPORT_UNSAVED);
        assert_eq!(import_apply_error(&body, false), IMPORT_FAILED);
        assert_eq!(
            import_apply_error(&CoreError::Store(StoreError::Io(ErrorKind::Other)), true),
            IMPORT_UNSAVED
        );
        assert_eq!(
            export_error(&CoreError::WrongPassword),
            EXPORT_WRONG_PASSWORD
        );
    }

    #[test]
    fn copied_note_names_the_clear_time_over_the_whole_range() {
        for secs in CLIPBOARD_MIN_SECS..=CLIPBOARD_MAX_SECS {
            let line = copied_note(secs);
            assert_eq!(
                line,
                format!("Copied. Holm clears the clipboard in {secs} seconds.")
            );
            assert!(
                !line.contains(['%', '<', '>', '/', '\\']),
                "not plain text: {line}"
            );
        }
        // Out-of-range times are clamped like the clear itself.
        assert!(copied_note(0).contains(" 5 seconds"));
        assert!(copied_note(u32::MAX).contains(" 90 seconds"));
    }

    #[test]
    fn eye_label_is_plain_text() {
        assert!(!EYE_LABEL.is_empty());
        assert!(!EYE_LABEL.contains(['{', '}', '%', '<', '>', '/', '\\']));
    }

    #[test]
    fn messages_have_no_placeholders() {
        for line in ALL {
            assert!(!line.is_empty());
            assert!(line.ends_with('.'), "{line}");
            assert!(
                !line.contains(['{', '}', '%', '<', '>', '/', '\\']),
                "not plain text: {line}"
            );
        }
        assert_eq!(
            throttle_line(&status(3, Some(2_000))).as_deref(),
            Some("Too many tries. Try again in 2 s.")
        );
    }

    #[test]
    fn lock_lines() {
        let note = |reason, discarded_unsaved| LockNote {
            reason,
            discarded_unsaved,
        };
        let five = Duration::from_secs(300);
        assert_eq!(lock_line(&note(LockReason::Manual, false), five), "Locked.");
        assert_eq!(
            lock_line(&note(LockReason::Idle, false), five),
            "Locked after 5 minutes without use."
        );
        assert_eq!(
            lock_line(&note(LockReason::Idle, false), Duration::from_secs(60)),
            "Locked after 1 minute without use."
        );
        assert_eq!(
            lock_line(&note(LockReason::Idle, false), Duration::from_secs(90)),
            "Locked after 90 seconds without use."
        );
        assert_eq!(
            lock_line(&note(LockReason::Minimised, false), five),
            "Locked when the window was minimised."
        );
        assert_eq!(
            lock_line(&note(LockReason::Idle, true), Duration::from_secs(600)),
            "Locked after 10 minutes without use. Unsaved changes were discarded."
        );
        assert_eq!(
            lock_line(&note(LockReason::Manual, true), five),
            "Locked. Unsaved changes were discarded."
        );
    }

    #[test]
    fn idle_warning_rounds_up() {
        assert_eq!(
            idle_warning(Duration::from_secs(30)),
            "Locking in 30 s because of no activity."
        );
        assert_eq!(
            idle_warning(Duration::from_millis(29_001)),
            "Locking in 30 s because of no activity."
        );
        assert_eq!(
            idle_warning(Duration::ZERO),
            "Locking in 1 s because of no activity."
        );
    }

    #[test]
    fn throttle_line_counts_and_rounds_up() {
        assert_eq!(throttle_line(&status(0, None)), None);
        assert_eq!(
            throttle_line(&status(1, None)).as_deref(),
            Some("1 failed try.")
        );
        assert_eq!(
            throttle_line(&status(2, None)).as_deref(),
            Some("2 failed tries.")
        );
        assert_eq!(
            throttle_line(&status(3, Some(1_001))).as_deref(),
            Some("Too many tries. Try again in 2 s.")
        );
        assert_eq!(
            throttle_line(&status(4, Some(1))).as_deref(),
            Some("Too many tries. Try again in 1 s.")
        );
        assert_eq!(
            throttle_line(&status(3, None)).as_deref(),
            Some("3 failed tries.")
        );
    }
}
