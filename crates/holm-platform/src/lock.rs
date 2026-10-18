//! [`InstanceLock`]: one Holm at a time per vault folder.
//!
//! Two Holm windows on one vault could overwrite each other's saves (spec §9). At
//! startup the GUI calls [`acquire`] on the vault's folder and keeps the lock for the
//! life of the app (Security decision, single instance). The lock is an exclusive,
//! non-blocking std [`File::try_lock`] on `<folder>/holm.lock`. Dropping the
//! [`InstanceLock`] releases it, and the OS releases it if the process dies, so a
//! crash never leaves a stale lock behind. (A child process that Holm starts at the
//! same moment holds a copy of the file until its `exec`, which delays the release
//! that long.)
//!
//! Rules kept here:
//! - the lock file is created with mode 0600 on Unix and is never written to: it is
//!   empty and holds no secret;
//! - the lock file must be a regular file: a symlink, a folder or a FIFO is refused,
//!   never followed or waited on;
//! - errors carry the [`std::io::ErrorKind`] only, never a path.

use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, ErrorKind};
use std::path::Path;

/// The lock file's name inside the vault folder.
pub const LOCK_FILE_NAME: &str = "holm.lock";

/// Why [`acquire`] did not get the lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockError {
    /// Another Holm (or another handle in this process) holds the lock.
    Held,
    /// The lock file could not be opened, created or locked. A lock path taken by
    /// something that is not a regular file is [`ErrorKind::InvalidInput`].
    Io(ErrorKind),
}

/// The exclusive lock on `holm.lock`. It is held until this value drops.
pub struct InstanceLock {
    /// The locked file. Closing it (on drop) releases the lock.
    #[expect(
        dead_code,
        reason = "kept only so the lock lives until this value drops"
    )]
    file: File,
}

impl fmt::Debug for InstanceLock {
    // Hand-written: `File`'s own `Debug` can print the path.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstanceLock").finish_non_exhaustive()
    }
}

/// Takes the exclusive lock on `<dir>/holm.lock`, creating the file if needed.
///
/// It does not wait: if the lock is taken, it returns [`LockError::Held`] at once.
///
/// # Errors
/// [`LockError::Held`] if another holder has the lock. [`LockError::Io`] if `dir` is
/// missing ([`ErrorKind::NotFound`]), if `holm.lock` is not a regular file
/// ([`ErrorKind::InvalidInput`]), or for any other OS error, by its kind.
pub fn acquire(dir: &Path) -> Result<InstanceLock, LockError> {
    let file = open_lock_file(&dir.join(LOCK_FILE_NAME)).map_err(|e| LockError::Io(e.kind()))?;
    match file.try_lock() {
        Ok(()) => Ok(InstanceLock { file }),
        Err(TryLockError::WouldBlock) => Err(LockError::Held),
        Err(TryLockError::Error(e)) => Err(LockError::Io(e.kind())),
    }
}

/// Opens `path` for writing, creating it with mode 0600 on Unix, but only if it is a
/// regular file. It never truncates or writes.
///
/// The entry is checked with `lstat` before the open, so an existing symlink is never
/// followed, and again after it: the path must still name the very file that was
/// opened (same device and inode on Unix). On Unix the open is non-blocking, so a
/// FIFO swapped in between cannot hang it.
fn open_lock_file(path: &Path) -> io::Result<File> {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => return Err(not_regular()),
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        if let Some(flag) = crate::fs_store::O_NONBLOCK {
            options.custom_flags(flag);
        }
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !opened.is_file() || !named.file_type().is_file() {
        return Err(not_regular());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (opened.dev(), opened.ino()) != (named.dev(), named.ino()) {
            return Err(not_regular());
        }
    }
    Ok(file)
}

/// The error for a lock path that is not a regular file.
fn not_regular() -> io::Error {
    io::Error::from(ErrorKind::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let first = acquire(dir.path()).unwrap();
        assert_eq!(acquire(dir.path()).err(), Some(LockError::Held));
        drop(first);
    }

    #[test]
    fn released_on_drop() {
        // A child process started by another test could hold a copy of the lock
        // file for a moment and keep the lock alive after the drop.
        let _no_children = crate::test_support::no_child_processes();
        let dir = tempfile::tempdir().unwrap();
        let first = acquire(dir.path()).unwrap();
        drop(first);
        let second = acquire(dir.path());
        assert!(second.is_ok(), "{second:?}");
    }

    #[test]
    fn missing_dir_is_io_not_found() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            acquire(&dir.path().join("missing")).err(),
            Some(LockError::Io(ErrorKind::NotFound))
        );
    }

    #[test]
    fn folder_in_place_of_lock_file_refused() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(LOCK_FILE_NAME)).unwrap();
        assert_eq!(
            acquire(dir.path()).err(),
            Some(LockError::Io(ErrorKind::InvalidInput))
        );
    }

    #[test]
    fn debug_shows_no_path() {
        let dir = tempfile::tempdir().unwrap();
        let lock = acquire(dir.path()).unwrap();
        let shown = format!("{lock:?}");
        assert_eq!(shown, "InstanceLock { .. }");
        assert!(!shown.contains(LOCK_FILE_NAME));
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let _lock = acquire(dir.path()).unwrap();
        let meta = fs::symlink_metadata(dir.path().join(LOCK_FILE_NAME)).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(meta.len(), 0, "the lock file is never written to");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_lock_file_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::os::unix::fs::symlink(&target, dir.path().join(LOCK_FILE_NAME)).unwrap();
        assert_eq!(
            acquire(dir.path()).err(),
            Some(LockError::Io(ErrorKind::InvalidInput))
        );
        assert!(!target.exists(), "the link was not followed");
    }

    #[cfg(unix)]
    #[test]
    fn fifo_lock_file_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join(LOCK_FILE_NAME);
        crate::test_support::make_fifo(&fifo);
        assert_eq!(
            acquire(dir.path()).err(),
            Some(LockError::Io(ErrorKind::InvalidInput))
        );
    }
}
