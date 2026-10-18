//! Opening the vault for one command, and finding an item by a short id.
//!
//! [`open`] takes the vault folder's instance lock before it asks for anything, so a
//! second Holm (the GUI or another CLI) is refused before a password is typed. The
//! lock is held until the returned [`Opened`] drops, which locks the session first.

use std::fs;
use std::io::{ErrorKind, Write};
use std::mem;
use std::path::Path;

use holm_core::envelope::VaultError;
use holm_core::error::CoreError;
use holm_core::item::ItemId;
use holm_core::search::{Query, View};
use holm_core::session::Session;
use holm_core::strength::MAX_MASTER_CHARS;
use holm_crypto::MasterPassword;
use holm_platform::fs_store::FsStore;
use holm_platform::lock::{self, InstanceLock};
use holm_platform::paths::ensure_vault_dir;
use zeroize::Zeroizing;

use crate::Env;
use crate::args::check_reference;
use crate::output::{CliError, dir_error, unlock_error};
use crate::term::Terminal;

/// The master password prompt.
pub const PASSWORD_PROMPT: &str = "Master password: ";
/// How many passwords one command asks for before it gives up.
pub const MAX_TRIES: usize = 3;
/// The most bytes a master password prompt takes: the strength policy's character
/// limit at 4 bytes per character.
pub const MAX_PASSWORD_BYTES: usize = MAX_MASTER_CHARS * 4;
/// Shown after each wrong password.
pub const WRONG_PASSWORD: &str = "That password didn't open this vault. Either the password is wrong, or the file was changed or damaged.";

/// An unlocked vault and the folder lock that guards it.
///
/// The session is declared first so it drops (and wipes its keys) before the lock is
/// released; `Drop` also locks it explicitly.
pub struct Opened {
    /// The unlocked session.
    pub session: Session<FsStore>,
    /// Held until this value drops.
    pub _lock: InstanceLock,
}

impl Drop for Opened {
    fn drop(&mut self) {
        // A one-shot command saves before it returns, so nothing is discarded here.
        let _ = self.session.lock();
    }
}

/// The folder that holds the vault, after [`ensure_vault_dir`] checked it.
fn vault_dir(path: &Path) -> Result<&Path, CliError> {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => Ok(dir),
        _ => Err(CliError::DirError),
    }
}

/// Checks the vault folder and takes its instance lock. Nothing is asked yet.
///
/// # Errors
/// [`CliError::DirPermissions`], [`CliError::DirError`], [`CliError::AlreadyOpen`]
/// or [`CliError::LockFailed`].
pub fn lock_folder(path: &Path) -> Result<InstanceLock, CliError> {
    ensure_vault_dir(path).map_err(dir_error)?;
    Ok(lock::acquire(vault_dir(path)?)?)
}

/// True if something is at `path` (a symlink is not followed).
#[must_use]
pub fn exists(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        // Anything but "not found" is treated as present, so `init` never writes
        // over it and `open` lets the unlock report the problem.
        Err(e) => e.kind() != ErrorKind::NotFound,
    }
}

/// Turns typed text into a master password without copying it.
pub(crate) fn master(mut typed: Zeroizing<String>) -> MasterPassword {
    MasterPassword::new(mem::take(&mut *typed))
}

/// Opens the vault at `path` for one command: checks the folder, takes the instance
/// lock, checks that a vault is there, then asks for the master password up to
/// [`MAX_TRIES`] times.
///
/// # Errors
/// The folder and lock errors of [`lock_folder`]; [`CliError::NoVault`] before any
/// prompt; a terminal error; [`CliError::TooManyTries`] after three wrong passwords;
/// [`CliError::Throttled`]; or another unlock error, as fixed text.
pub fn open(
    path: &Path,
    env: &Env,
    term: &mut dyn Terminal,
    err: &mut dyn Write,
) -> Result<Opened, CliError> {
    let lock = lock_folder(path)?;
    if !exists(path) {
        return Err(CliError::NoVault);
    }
    let mut session = Session::new(FsStore::new(path), (env.clock)());
    for _ in 0..MAX_TRIES {
        if unlock_once(&mut session, term)? {
            return Ok(Opened {
                session,
                _lock: lock,
            });
        }
        writeln!(err, "{WRONG_PASSWORD}")?;
    }
    Err(CliError::TooManyTries)
}

/// Asks for the master password once and tries it. `Ok(false)` is a wrong password
/// (or a changed or damaged file); the caller says so. A failure counts against the
/// session's throttle, which outlives a lock, so `holm shell` keeps one throttle for
/// its whole life.
///
/// # Errors
/// A terminal error, [`CliError::Throttled`], or another unlock error, as fixed text.
pub fn unlock_once(
    session: &mut Session<FsStore>,
    term: &mut dyn Terminal,
) -> Result<bool, CliError> {
    let password = master(term.secret(PASSWORD_PROMPT, MAX_PASSWORD_BYTES)?);
    match session.unlock(&password) {
        Ok(()) => Ok(true),
        Err(CoreError::WrongPassword | CoreError::Vault(VaultError::WrongPasswordOrCorrupt)) => {
            Ok(false)
        }
        Err(e) => Err(unlock_error(&e)),
    }
}

/// Finds the one item in `view` whose id starts with `reference`.
///
/// # Errors
/// [`CliError::Usage`] if `reference` is not 6 to 32 lowercase hex digits,
/// [`CliError::NotFound`], [`CliError::Ambiguous`], or [`CliError::Failed`] if the
/// session is locked.
pub fn resolve(
    session: &Session<FsStore>,
    reference: &str,
    view: View,
) -> Result<ItemId, CliError> {
    check_reference(reference)?;
    match_reference(reference, ids_in(session, view)?)
}

/// Like [`resolve`], over the active items and the Trash together. A prefix that
/// matches one item in each is [`CliError::Ambiguous`].
///
/// # Errors
/// As [`resolve`].
pub fn resolve_any(session: &Session<FsStore>, reference: &str) -> Result<ItemId, CliError> {
    check_reference(reference)?;
    let mut ids = ids_in(session, View::Active)?;
    ids.extend(ids_in(session, View::Trash)?);
    match_reference(reference, ids)
}

fn ids_in(session: &Session<FsStore>, view: View) -> Result<Vec<ItemId>, CliError> {
    let query = Query {
        view,
        ..Query::default()
    };
    let hits = session.search(&query).map_err(|_| CliError::Failed)?;
    Ok(hits.iter().map(|h| h.id).collect())
}

/// The one id in `ids` that starts with `reference`.
///
/// # Errors
/// [`CliError::Usage`] for a malformed reference, [`CliError::NotFound`] for no
/// match, [`CliError::Ambiguous`] for more than one.
pub fn match_reference(
    reference: &str,
    ids: impl IntoIterator<Item = ItemId>,
) -> Result<ItemId, CliError> {
    check_reference(reference)?;
    let mut found = None;
    let mut count = 0_usize;
    for id in ids {
        if id.to_hex().starts_with(reference) {
            count += 1;
            found = Some(id);
        }
    }
    match (count, found) {
        (1, Some(id)) => Ok(id),
        (0, _) => Err(CliError::NotFound),
        _ => Err(CliError::Ambiguous { count }),
    }
}
