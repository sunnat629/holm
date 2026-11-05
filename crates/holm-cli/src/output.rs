//! What the CLI prints: its errors (fixed text only), and the helpers that make
//! vault text and times safe and readable on a terminal.

use std::borrow::Cow;
use std::fmt;
use std::io::ErrorKind;

use holm_core::body::BodyError;
use holm_core::envelope::VaultError;
use holm_core::error::CoreError;
use holm_core::import::ImportError;
use holm_core::item::Timestamp;
use holm_core::rules::{Field, FieldError};
use holm_core::store::StoreError;
use holm_platform::lock::LockError;
use holm_platform::tty::TtyError;

use crate::args::UsageError;

/// Why a command failed. Every variant prints fixed text: never a path, a value
/// from the vault, a typed secret or a library's message.
#[derive(Debug)]
pub enum CliError {
    /// The command line is wrong (exit code 2).
    Usage(UsageError),
    /// No `--vault` and no default vault path on this system.
    NoVaultPath,
    /// The vault folder is open to other users.
    DirPermissions,
    /// The vault folder could not be made or used.
    DirError,
    /// Another Holm holds the vault folder's lock.
    AlreadyOpen,
    /// The lock file could not be opened or locked.
    LockFailed,
    /// There is no vault file at the path.
    NoVault,
    /// `init` found a vault already there.
    VaultExists,
    /// No controlling terminal to ask on.
    NoTerminal,
    /// Ctrl-C, Ctrl-D, or the terminal closed.
    Cancelled,
    /// The typed line was longer than allowed.
    InputTooLong,
    /// The typed line was not valid text.
    InputNotText,
    /// This system has no terminal support.
    TerminalUnsupported,
    /// Any other terminal error.
    TerminalFailed,
    /// Three wrong passwords in a row.
    TooManyTries,
    /// The throttle refused the attempt.
    Throttled {
        /// Seconds to wait.
        retry_after_secs: u64,
    },
    /// Not enough memory for the key derivation.
    NotEnoughMemory,
    /// The vault's key-derivation costs are outside the policy.
    KdfPolicy,
    /// The file is not a Holm vault, or it is damaged.
    NotAVault,
    /// The vault was written by a newer Holm.
    NewerVault,
    /// The vault file could not be read.
    ReadFailed,
    /// Any other unlock failure.
    UnlockFailed,
    /// `init`: the password is below the strength policy.
    WeakPassword,
    /// `init`: the two passwords differ.
    PasswordsDiffer,
    /// `init`: the new vault could not be written.
    SaveFailed,
    /// `init`: the file was written but the folder sync failed.
    CreateMaybeSaved,
    /// `init`: any other failure.
    CreateFailed,
    /// No item matches the reference.
    NotFound,
    /// More than one item matches the reference.
    Ambiguous {
        /// How many items match.
        count: usize,
    },
    /// `--category` names no category.
    UnknownCategory,
    /// The generator failed.
    GenerateFailed,
    /// Writing the output failed (for example a closed pipe).
    Output,
    /// Any other error.
    Failed,
    /// A password typed again to confirm an action is wrong.
    WrongPassword,
    /// A typed confirmation was not the word asked for.
    NotConfirmed,
    /// An option that only fits another item type.
    TypeChange,
    /// A field breaks an item rule.
    Field(FieldError),
    /// Two entries of a new secret differ.
    SecretsDiffer,
    /// The item is in the Trash.
    InTrash,
    /// `rm --forever` on an item outside the Trash.
    NotInTrash,
    /// The vault is at its item limit.
    TooManyItems,
    /// The vault would be too big to save; the change was undone.
    TooLargeToSave,
    /// A save failed after the change was made in memory.
    NotSaved,
    /// `import`: the file is not there.
    ImportFileMissing,
    /// `import`: the path is a folder, FIFO, device or socket.
    ImportNotAFile,
    /// `import`: the file is over the import limit.
    ImportTooLarge,
    /// `import`: no permission to read the file.
    ImportNoAccess,
    /// `import`: any other read error.
    ImportReadFailed,
    /// `import`: the whole file was refused.
    Import(ImportError),
    /// `import`: the items would take the vault over its item limit.
    ImportTooManyItems,
    /// `import`: the vault would be too big to save with the items.
    ImportTooLargeToSave,
    /// `import`: the items were added in memory but the save failed.
    ImportNotSaved,
    /// `export`: something is already at the path.
    FileExists,
    /// `export`: writing the file failed.
    ExportWriteFailed,
    /// `export --backup`: writing the backup failed.
    BackupFailed,
    /// `--copy` on a system with no supported clipboard.
    NoClipboard,
    /// The clipboard did not take the value.
    CopyFailed,
    /// The clipboard still holds the value after the clear.
    ClearFailed,
    /// `--copy` names a field this item type does not have.
    NoSuchField,
    /// `--copy` names an empty field.
    EmptyField,
    /// `passwd`: the change failed and the old password still opens the vault.
    PasswordChangeKept,
    /// `passwd`: the new password may now be needed.
    PasswordChangeUncertain,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            CliError::Usage(u) => u.0,
            CliError::NoVaultPath => {
                "Holm has no default vault location on this system. Give one with --vault PATH."
            }
            CliError::DirPermissions => {
                "Holm can't use this folder because other users can change it. Fix the folder's permissions and try again."
            }
            CliError::DirError => {
                "Holm couldn't use the folder for its vault. Check that the folder exists and is a normal folder."
            }
            CliError::AlreadyOpen => {
                "Holm is already open on this vault. Close the other Holm first."
            }
            CliError::LockFailed => "Holm couldn't lock the vault folder.",
            CliError::NoVault => "Holm found no vault here. Run holm init to make one.",
            CliError::VaultExists => "A vault already exists here. Nothing was changed.",
            CliError::NoTerminal => {
                "Holm needs a terminal to ask for the password. It never reads one from a pipe, a file or the command line."
            }
            CliError::Cancelled => "Cancelled.",
            CliError::InputTooLong => "That was too long. Nothing was kept.",
            CliError::InputNotText => "That wasn't valid text. Nothing was kept.",
            CliError::TerminalUnsupported => "Holm can't ask for a password on this system yet.",
            CliError::TerminalFailed => "Holm couldn't use the terminal.",
            CliError::TooManyTries => "Three wrong passwords. Run the command again to retry.",
            CliError::Throttled { retry_after_secs } => {
                return write!(
                    f,
                    "Too many wrong passwords. Wait {retry_after_secs} seconds and try again."
                );
            }
            CliError::NotEnoughMemory => {
                "Holm didn't have enough memory for this. Close some apps and try again."
            }
            CliError::KdfPolicy => {
                "This vault's security settings are outside what Holm accepts, so Holm won't open it."
            }
            CliError::NotAVault => "This file isn't a Holm vault, or it is damaged.",
            CliError::NewerVault => "This vault was made by a newer Holm. Update Holm to open it.",
            CliError::ReadFailed => "Holm couldn't read the vault file.",
            CliError::UnlockFailed => "Holm couldn't open this vault.",
            CliError::WeakPassword => {
                "This master password is too easy to guess. Choose a stronger one."
            }
            CliError::PasswordsDiffer => "The two passwords don't match. Nothing was made.",
            CliError::SaveFailed => "Holm couldn't save the new vault. Try again.",
            CliError::CreateMaybeSaved => {
                "Holm may have saved your vault anyway. Try to unlock it with the password you just chose."
            }
            CliError::CreateFailed => "Holm couldn't create the vault. Try again.",
            CliError::NotFound => "No item matches that id.",
            CliError::Ambiguous { count } => {
                return write!(
                    f,
                    "{count} items match that id. Type more of it, as holm list shows it."
                );
            }
            CliError::UnknownCategory => "No category has that name.",
            CliError::GenerateFailed => "Holm couldn't generate a value. Try again.",
            CliError::Output => "Holm couldn't write its output.",
            CliError::Failed => "Something went wrong. Nothing was changed.",
            CliError::WrongPassword => "That password is wrong. Nothing was done.",
            CliError::NotConfirmed => "Not confirmed. Nothing was changed.",
            CliError::TypeChange => {
                "That option doesn't fit this item's type, and an item's type can't be changed. Nothing was changed."
            }
            CliError::Field(e) => return field_message(*e, f),
            CliError::SecretsDiffer => "The two entries don't match. Nothing was changed.",
            CliError::InTrash => "That item is in the Trash. Nothing was changed.",
            CliError::NotInTrash => "That item isn't in the Trash. Nothing was changed.",
            CliError::TooManyItems => "The vault is full (50000 items). Nothing was changed.",
            CliError::TooLargeToSave => {
                "The vault would be too large to save. Nothing was changed."
            }
            CliError::NotSaved => {
                "Holm couldn't confirm the save, so the change may not be in the vault file. Run holm list to check."
            }
            CliError::ImportFileMissing => "Holm found no file to import there.",
            CliError::ImportNotAFile => "That isn't a regular file, so Holm won't import it.",
            CliError::ImportTooLarge => {
                "That file is over Holm's 16 MiB import limit. Nothing was imported."
            }
            CliError::ImportNoAccess => "Holm isn't allowed to read that file.",
            CliError::ImportReadFailed => "Holm couldn't read that file. Nothing was imported.",
            CliError::Import(e) => return import_message(e, f),
            CliError::ImportTooManyItems => {
                "These items would take the vault over 50000 items. Nothing was imported."
            }
            CliError::ImportTooLargeToSave => {
                "The vault would be too large to save with these items. Nothing was imported."
            }
            CliError::ImportNotSaved => {
                "Holm couldn't confirm the save, so the imported items may not be in the vault file. Run holm list to check, and keep the file until they are there."
            }
            CliError::FileExists => {
                "Something is already at that path. Holm never writes over a file. Choose a new name."
            }
            CliError::ExportWriteFailed => {
                "Holm couldn't write the file. Check the folder, and delete any partial file left there."
            }
            CliError::BackupFailed => {
                "Holm couldn't write the backup. Check the folder, and delete any partial file left there."
            }
            CliError::NoClipboard => {
                "Holm can only copy to the clipboard on macOS. Nothing was copied."
            }
            CliError::CopyFailed => "Holm couldn't put the value on the clipboard.",
            CliError::ClearFailed => {
                "Holm couldn't clear the clipboard. Copy something else to replace the value."
            }
            CliError::NoSuchField => "This item has no such field. Nothing was copied.",
            CliError::EmptyField => "That field is empty. Nothing was copied.",
            CliError::PasswordChangeKept => {
                "Holm couldn't save the new master password. The old one still opens the vault."
            }
            CliError::PasswordChangeUncertain => {
                "Holm couldn't confirm the change. The new master password may now be needed to open the vault. If it doesn't work, try the old one."
            }
        };
        f.write_str(text)
    }
}

impl From<UsageError> for CliError {
    fn from(e: UsageError) -> CliError {
        CliError::Usage(e)
    }
}

impl From<TtyError> for CliError {
    fn from(e: TtyError) -> CliError {
        match e {
            TtyError::NoTerminal => CliError::NoTerminal,
            TtyError::Cancelled | TtyError::EndOfInput => CliError::Cancelled,
            TtyError::TooLong => CliError::InputTooLong,
            TtyError::NotUtf8 => CliError::InputNotText,
            TtyError::Unsupported => CliError::TerminalUnsupported,
            TtyError::Io(_) => CliError::TerminalFailed,
        }
    }
}

impl From<LockError> for CliError {
    fn from(e: LockError) -> CliError {
        match e {
            LockError::Held => CliError::AlreadyOpen,
            LockError::Io(_) => CliError::LockFailed,
        }
    }
}

impl From<std::io::Error> for CliError {
    /// Only for writes to the output streams.
    fn from(_: std::io::Error) -> CliError {
        CliError::Output
    }
}

/// The folder check's error, as the GUI maps it.
#[must_use]
pub fn dir_error(e: StoreError) -> CliError {
    match e {
        StoreError::Io(ErrorKind::PermissionDenied) => CliError::DirPermissions,
        _ => CliError::DirError,
    }
}

/// An unlock error other than a wrong password, as the GUI maps it.
#[must_use]
pub fn unlock_error(e: &CoreError) -> CliError {
    match e {
        CoreError::Vault(VaultError::OutOfMemory) => CliError::NotEnoughMemory,
        CoreError::Vault(VaultError::KdfPolicy(_)) => CliError::KdfPolicy,
        CoreError::Vault(VaultError::Format(_) | VaultError::BadPadding)
        | CoreError::Store(StoreError::NotARegularFile) => CliError::NotAVault,
        CoreError::Body(BodyError::NewerSchema(_)) => CliError::NewerVault,
        CoreError::NoVault => CliError::NoVault,
        CoreError::Store(_) => CliError::ReadFailed,
        CoreError::Throttled { retry_after_secs } => CliError::Throttled {
            retry_after_secs: *retry_after_secs,
        },
        _ => CliError::UnlockFailed,
    }
}

/// A create error, as the GUI maps it (`maybe_saved`: the vault file exists now).
#[must_use]
pub fn create_error(e: &CoreError, maybe_saved: bool) -> CliError {
    match e {
        CoreError::Store(_) if maybe_saved => CliError::CreateMaybeSaved,
        CoreError::Store(StoreError::Io(ErrorKind::PermissionDenied)) => CliError::DirPermissions,
        CoreError::VaultExists => CliError::VaultExists,
        CoreError::WeakPassword(_) => CliError::WeakPassword,
        CoreError::Vault(VaultError::OutOfMemory) => CliError::NotEnoughMemory,
        CoreError::Store(_) => CliError::SaveFailed,
        _ => CliError::CreateFailed,
    }
}

/// A field's name in a sentence.
fn field_word(field: Field) -> &'static str {
    match field {
        Field::Title => "title",
        Field::Username => "username",
        Field::Password => "password",
        Field::Url => "web address",
        Field::Notes => "notes",
        Field::Chain => "chain",
        Field::Address => "address",
        Field::Memo => "memo",
        Field::Phrase => "recovery phrase",
        Field::Body => "note",
        Field::CategoryName => "category name",
        Field::CustomLabel => "field name",
        Field::CustomValue => "field value",
        Field::CustomDate => "date",
    }
}

fn field_message(e: FieldError, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match e {
        FieldError::Empty(Field::CustomLabel) => f.write_str("The field name can't be empty"),
        FieldError::TooLong(Field::CustomValue) => f.write_str("The field value is too long"),
        FieldError::BadDate => f.write_str("That date is not a real calendar day"),
        FieldError::TooManyFields => f.write_str("An item can have at most 10 custom fields"),
        FieldError::NoSuchIndex => f.write_str("That field is not on the item"),
        FieldError::Empty(field) => {
            write!(
                f,
                "The {} can't be empty. Nothing was changed.",
                field_word(field)
            )
        }
        FieldError::TooLong(field) => {
            write!(
                f,
                "The {} is too long. Nothing was changed.",
                field_word(field)
            )
        }
        FieldError::ForbiddenChar(field) => write!(
            f,
            "The {} has a character Holm doesn't allow there. Nothing was changed.",
            field_word(field)
        ),
        FieldError::TooManyUrls => {
            f.write_str("A login can have at most 32 web addresses. Nothing was changed.")
        }
        FieldError::Reserved(field) => {
            write!(
                f,
                "That {} is reserved. Nothing was changed.",
                field_word(field)
            )
        }
    }
}

fn import_message(e: &ImportError, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match e {
        ImportError::TooLarge => {
            f.write_str("That file is over Holm's 16 MiB import limit. Nothing was imported.")
        }
        ImportError::NotUtf8 => f.write_str("That file isn't UTF-8 text. Nothing was imported."),
        ImportError::Empty => f.write_str("That file is empty. Nothing was imported."),
        ImportError::UnknownColumns { count: 0 } => {
            f.write_str("That file has no title column. Nothing was imported.")
        }
        ImportError::UnknownColumns { count } => write!(
            f,
            "That file has {count} column names Holm doesn't know. Nothing was imported."
        ),
        ImportError::DuplicateColumn => {
            f.write_str("That file names the same column twice. Nothing was imported.")
        }
        ImportError::TooManyColumns => {
            f.write_str("That file has more than 64 columns. Nothing was imported.")
        }
        ImportError::TooManyRows => {
            f.write_str("That file has more than 50000 rows. Nothing was imported.")
        }
        ImportError::Malformed { line } => write!(
            f,
            "That file isn't valid CSV or JSON at line {line}. Nothing was imported."
        ),
    }
}

/// An error from a read or password check, without claims about saving a change.
#[must_use]
pub fn read_error(e: &CoreError) -> CliError {
    match e {
        CoreError::WrongPassword | CoreError::Vault(VaultError::WrongPasswordOrCorrupt) => {
            CliError::WrongPassword
        }
        CoreError::Throttled { retry_after_secs } => CliError::Throttled {
            retry_after_secs: *retry_after_secs,
        },
        CoreError::NotFound | CoreError::NotAPhrase => CliError::NotFound,
        _ => CliError::Failed,
    }
}

/// An error from a change to the vault (add, edit, rm, import and so on), as fixed
/// text. A save error other than "too large" means the change was made in memory and
/// may not be on disk: [`CliError::NotSaved`], never "nothing was changed".
#[must_use]
pub fn write_error(e: &CoreError) -> CliError {
    match e {
        CoreError::Field(f) => CliError::Field(*f),
        CoreError::TypeChange => CliError::TypeChange,
        CoreError::InTrash => CliError::InTrash,
        CoreError::NotInTrash => CliError::NotInTrash,
        CoreError::NotFound | CoreError::NotAPhrase => CliError::NotFound,
        CoreError::UnknownCategory => CliError::UnknownCategory,
        CoreError::TooManyItems => CliError::TooManyItems,
        CoreError::Vault(VaultError::TooLargeToSave) => CliError::TooLargeToSave,
        CoreError::Store(_) | CoreError::Body(_) | CoreError::Vault(_) => CliError::NotSaved,
        CoreError::WrongPassword => CliError::WrongPassword,
        CoreError::Throttled { retry_after_secs } => CliError::Throttled {
            retry_after_secs: *retry_after_secs,
        },
        CoreError::WeakPassword(_) => CliError::WeakPassword,
        CoreError::VaultExists => CliError::FileExists,
        _ => CliError::Failed,
    }
}

impl CliError {
    /// The process exit code: 2 for a usage error, 1 for everything else.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::Usage(_) => 2,
            _ => 1,
        }
    }
}

/// `text` with every control character and every bidirectional formatting character
/// replaced by U+FFFD, so a stored title can't move the cursor, clear the screen or
/// reorder what the terminal shows. The core already refuses these in fields; this is
/// a second line of defence for output. Invisible characters and Unicode line
/// separators are dropped.
#[must_use]
pub fn clean(text: &str) -> Cow<'_, str> {
    if !text
        .chars()
        .any(|c| unsafe_for_terminal(c) || invisible_or_separator(c))
    {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.chars()
            .filter(|&c| !invisible_or_separator(c))
            .map(|c| {
                if unsafe_for_terminal(c) {
                    '\u{fffd}'
                } else {
                    c
                }
            })
            .collect(),
    )
}

fn invisible_or_separator(c: char) -> bool {
    matches!(
        c,
        '\u{2028}' | '\u{2029}' | '\u{200b}'..='\u{200d}' | '\u{2060}' | '\u{feff}'
    )
}

fn unsafe_for_terminal(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

/// A Unix time as `YYYY-MM-DD HH:MM:SS UTC`.
#[must_use]
pub fn utc(t: Timestamp) -> String {
    let secs = t.0;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to a (year, month, day) date in the proleptic Gregorian
/// calendar (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_dates() {
        assert_eq!(utc(Timestamp(0)), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(Timestamp(951_782_400)), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc(Timestamp(1_700_000_000)), "2023-11-14 22:13:20 UTC");
        assert_eq!(utc(Timestamp(-1)), "1969-12-31 23:59:59 UTC");
    }

    #[test]
    fn clean_replaces_terminal_controls() {
        assert!(matches!(clean("Mail"), Cow::Borrowed("Mail")));
        assert_eq!(
            clean("a\tb\x1b[2Jc\u{202e}d"),
            "a\u{fffd}b\u{fffd}[2Jc\u{fffd}d"
        );
    }

    #[test]
    fn clean_drops_invisible_and_separators() {
        assert_eq!(
            clean("a\u{2028}\u{2029}\u{200b}\u{200c}\u{200d}\u{2060}\u{feff}b"),
            "ab"
        );
        assert!(matches!(clean("café"), Cow::Borrowed("café")));
    }

    #[test]
    fn read_only_errors_say_nothing_about_saving() {
        for error in [
            CoreError::Store(StoreError::NotFound),
            CoreError::Body(holm_core::body::BodyError::Malformed),
            CoreError::Vault(VaultError::TooLargeToSave),
            CoreError::Vault(VaultError::OutOfMemory),
            CoreError::Locked,
            CoreError::WrongPassword,
            CoreError::NotAPhrase,
            CoreError::Throttled {
                retry_after_secs: 2,
            },
        ] {
            let message = read_error(&error).to_string().to_lowercase();
            assert!(!message.contains("sav"), "{message}");
        }
        assert!(matches!(
            read_error(&CoreError::WrongPassword),
            CliError::WrongPassword
        ));
        assert!(matches!(
            read_error(&CoreError::NotAPhrase),
            CliError::NotFound
        ));
    }

    #[test]
    fn messages_hold_no_placeholders() {
        let all = [
            CliError::NoVaultPath,
            CliError::NoTerminal,
            CliError::Throttled {
                retry_after_secs: 2,
            },
            CliError::Ambiguous { count: 3 },
        ];
        assert_eq!(
            all[2].to_string(),
            "Too many wrong passwords. Wait 2 seconds and try again."
        );
        assert!(all[3].to_string().starts_with("3 items"));
        for e in all {
            assert!(!e.to_string().contains('{'));
        }
    }
}
