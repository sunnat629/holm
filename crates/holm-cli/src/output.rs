//! What the CLI prints: its errors (fixed text only), and the helpers that make
//! vault text and times safe and readable on a terminal.

use std::borrow::Cow;
use std::fmt;
use std::io::ErrorKind;

use holm_core::body::BodyError;
use holm_core::envelope::VaultError;
use holm_core::error::CoreError;
use holm_core::item::Timestamp;
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
    /// A command whose handler is not built yet.
    NotReady,
    /// Any other error.
    Failed,
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
            CliError::NotReady => "That command isn't ready yet.",
            CliError::Failed => "Something went wrong. Nothing was changed.",
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
            TtyError::Cancelled => CliError::Cancelled,
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
/// a second line of defence for output.
#[must_use]
pub fn clean(text: &str) -> Cow<'_, str> {
    if !text.chars().any(unsafe_for_terminal) {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.chars()
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
