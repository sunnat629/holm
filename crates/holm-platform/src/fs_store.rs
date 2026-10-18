//! [`FsStore`]: the vault as one file on disk, with durable, crash-safe writes.
//!
//! A save never writes into the vault file itself. It writes a new temp file in the
//! same directory, syncs it, renames it over the vault, then syncs the directory
//! (Security decision, durable writes). A rename within one directory is atomic, so
//! after a crash at any point the vault holds the old bytes or the new bytes, never a
//! mix. A temp file left by a crash is removed on the next unlock by
//! [`VaultStore::remove_stale_temps`].
//!
//! Rules kept here:
//! - temps are named `<file_name>.tmp-<16 lowercase hex digits>` and opened with
//!   `create_new` (never reusing a file) and, on Unix, mode 0600;
//! - the vault must be a regular file: a symlink or a folder is refused, never
//!   followed;
//! - on Unix a write refuses a world-writable directory, where another user could
//!   swap or delete the vault;
//! - errors carry the [`std::io::ErrorKind`] only, never a path.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use holm_core::format::MAX_FILE_LEN;
use holm_core::store::{StoreError, VaultStore};
use holm_crypto::random_array;

/// [`MAX_FILE_LEN`] as a file length. A `usize` always fits in a `u64` on the
/// platforms Holm supports.
const MAX_LEN_U64: u64 = MAX_FILE_LEN as u64;

/// Between the vault's file name and the random part of a temp name.
const TEMP_INFIX: &[u8] = b".tmp-";

/// Random bytes in a temp name; each becomes two hex digits.
const TEMP_RANDOM_BYTES: usize = 8;

/// One step of [`VaultStore::replace`], in the order they happen. A test observer
/// sees each step right after it completes (see [`FsStore::with_observer`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveStep {
    /// The temp file exists and is empty.
    TempCreated,
    /// The first half of the bytes (`len / 2`) is written to the temp file.
    TempHalfWritten,
    /// Every byte is written to the temp file.
    TempWritten,
    /// The temp file is synced to the disk.
    TempSynced,
    /// The temp file has been renamed over the vault.
    Renamed,
    /// The directory is synced, so the rename itself is on disk. Unix only.
    DirSynced,
}

impl SaveStep {
    /// Every step, in order.
    pub const ALL: [SaveStep; 6] = [
        SaveStep::TempCreated,
        SaveStep::TempHalfWritten,
        SaveStep::TempWritten,
        SaveStep::TempSynced,
        SaveStep::Renamed,
        SaveStep::DirSynced,
    ];

    /// The step's name, the same as its variant name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            SaveStep::TempCreated => "TempCreated",
            SaveStep::TempHalfWritten => "TempHalfWritten",
            SaveStep::TempWritten => "TempWritten",
            SaveStep::TempSynced => "TempSynced",
            SaveStep::Renamed => "Renamed",
            SaveStep::DirSynced => "DirSynced",
        }
    }
}

/// A test hook that sees each [`SaveStep`] of a `replace`.
type Observer = Box<dyn FnMut(SaveStep) + Send>;

/// The vault file at one path, read and written through [`VaultStore`].
pub struct FsStore {
    path: PathBuf,
    observer: Option<Observer>,
}

impl fmt::Debug for FsStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsStore")
            .field("path", &self.path)
            .field("observer", &self.observer.is_some())
            .finish()
    }
}

/// An I/O error, reduced to its kind so no path leaks into messages.
fn io_err(e: &io::Error) -> StoreError {
    StoreError::Io(e.kind())
}

/// Lowercase hex, two digits per byte.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Opens `path` for writing only if it does not exist yet, mode 0600 on Unix.
/// `create_new` also refuses a symlink at `path`, so nothing is followed.
fn create_exclusive(path: &Path) -> Result<File, StoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|e| match e.kind() {
        ErrorKind::AlreadyExists => StoreError::AlreadyExists,
        _ => io_err(&e),
    })
}

/// Writes all of `bytes` to a new file and syncs it.
fn write_all_synced(file: &mut File, bytes: &[u8]) -> Result<(), StoreError> {
    file.write_all(bytes).map_err(|e| io_err(&e))?;
    file.sync_all().map_err(|e| io_err(&e))
}

impl FsStore {
    /// A store for the vault at `path`. Touches nothing on disk.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> FsStore {
        FsStore {
            path: path.into(),
            observer: None,
        }
    }

    /// Like [`FsStore::new`], but `observer` is called after each step of every
    /// `replace`. For crash tests: an observer that exits the process stops a save
    /// at an exact point.
    #[must_use]
    pub fn with_observer(path: impl Into<PathBuf>, observer: Observer) -> FsStore {
        FsStore {
            path: path.into(),
            observer: Some(observer),
        }
    }

    /// Where the vault file lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn emit(&mut self, step: SaveStep) {
        if let Some(observer) = self.observer.as_mut() {
            observer(step);
        }
    }

    /// The directory holding the vault (`.` for a bare file name).
    fn dir(&self) -> &Path {
        match self.path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        }
    }

    /// The vault's file name. A path with none (such as `/` or `..`) cannot be a
    /// vault file.
    fn file_name(&self) -> Result<&OsStr, StoreError> {
        self.path
            .file_name()
            .ok_or(StoreError::Io(ErrorKind::InvalidInput))
    }

    /// A fresh temp path: `<file_name>.tmp-<16 hex>` in the vault's directory.
    fn temp_path(&self) -> Result<PathBuf, StoreError> {
        let mut name = OsString::from(self.file_name()?);
        let random =
            random_array::<TEMP_RANDOM_BYTES>().map_err(|_| StoreError::Io(ErrorKind::Other))?;
        name.push(".tmp-");
        name.push(hex(&random));
        Ok(self.dir().join(name))
    }

    /// True only for `<file_name>.tmp-` followed by exactly 16 lowercase hex digits.
    fn is_own_temp_name(&self, candidate: &OsStr) -> bool {
        let Ok(name) = self.file_name() else {
            return false;
        };
        candidate
            .as_encoded_bytes()
            .strip_prefix(name.as_encoded_bytes())
            .and_then(|rest| rest.strip_prefix(TEMP_INFIX))
            .is_some_and(|digits| {
                digits.len() == TEMP_RANDOM_BYTES.saturating_mul(2)
                    && digits
                        .iter()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            })
    }

    /// Refuses a vault path that exists but is not a regular file. A missing file
    /// is fine (`replace` creates it).
    fn check_target(&self) -> Result<(), StoreError> {
        match fs::symlink_metadata(&self.path) {
            Ok(m) if m.file_type().is_file() => Ok(()),
            Ok(_) => Err(StoreError::NotARegularFile),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(&e)),
        }
    }

    /// On Unix, refuses to write into a world-writable directory, where another
    /// user could delete or swap the vault. The directory itself may be reached
    /// through a symlink (macOS `/var` is one).
    fn check_dir(&self) -> Result<(), StoreError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(self.dir()).map_err(|e| io_err(&e))?;
            if meta.permissions().mode() & 0o002 != 0 {
                return Err(StoreError::Io(ErrorKind::PermissionDenied));
            }
        }
        Ok(())
    }

    /// Syncs the directory so a rename or new link is on disk. On Unix only;
    /// elsewhere there is no portable way, and this does nothing.
    ///
    /// `ErrorKind::Unsupported` counts as success: some FAT and exFAT volumes cannot
    /// sync a directory (Security decision, durable writes). Any other error fails.
    fn sync_dir(&self) -> Result<(), StoreError> {
        #[cfg(unix)]
        {
            let dir = File::open(self.dir()).map_err(|e| io_err(&e))?;
            match dir.sync_all() {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::Unsupported => {}
                Err(e) => return Err(io_err(&e)),
            }
        }
        Ok(())
    }

    /// Writes `bytes` into the open temp file, emitting the write and sync steps.
    fn fill_temp(&mut self, temp: &mut File, bytes: &[u8]) -> Result<(), StoreError> {
        let (first, second) = bytes.split_at(bytes.len() / 2);
        temp.write_all(first).map_err(|e| io_err(&e))?;
        self.emit(SaveStep::TempHalfWritten);
        temp.write_all(second).map_err(|e| io_err(&e))?;
        self.emit(SaveStep::TempWritten);
        temp.sync_all().map_err(|e| io_err(&e))?;
        self.emit(SaveStep::TempSynced);
        Ok(())
    }
}

impl VaultStore for FsStore {
    fn read(&mut self) -> Result<Vec<u8>, StoreError> {
        let before = match fs::symlink_metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(StoreError::NotFound),
            Err(e) => return Err(io_err(&e)),
        };
        if !before.file_type().is_file() {
            return Err(StoreError::NotARegularFile);
        }
        // Refused before the file is even opened, so a huge file costs nothing.
        if before.len() > MAX_LEN_U64 {
            return Err(StoreError::TooLarge);
        }
        let file = File::open(&self.path).map_err(|e| match e.kind() {
            ErrorKind::NotFound => StoreError::NotFound,
            _ => io_err(&e),
        })?;
        // The path may have been swapped between the check and the open. Check what
        // was actually opened: a regular file, and on Unix the same one.
        let opened = file.metadata().map_err(|e| io_err(&e))?;
        if !opened.is_file() {
            return Err(StoreError::NotARegularFile);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if opened.dev() != before.dev() || opened.ino() != before.ino() {
                return Err(StoreError::NotARegularFile);
            }
        }
        let expected = usize::try_from(opened.len()).map_or(MAX_FILE_LEN, |n| n.min(MAX_FILE_LEN));
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected)
            .map_err(|_| StoreError::Io(ErrorKind::OutOfMemory))?;
        // The file may grow while we read; read at most one byte past the limit.
        file.take(MAX_LEN_U64.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| io_err(&e))?;
        if bytes.len() > MAX_FILE_LEN {
            return Err(StoreError::TooLarge);
        }
        Ok(bytes)
    }

    /// Writes a temp file, syncs it, renames it over the vault and syncs the
    /// directory. Before the rename any error removes the temp and leaves the vault
    /// untouched. A directory-sync error comes after the rename: the call fails, the
    /// file already holds the new bytes in full, and the session stays dirty, so the
    /// next save writes them again.
    fn replace(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        if bytes.len() > MAX_FILE_LEN {
            return Err(StoreError::TooLarge);
        }
        self.check_target()?;
        self.check_dir()?;
        let temp = self.temp_path()?;
        let mut file = create_exclusive(&temp)?;
        self.emit(SaveStep::TempCreated);
        let filled = self.fill_temp(&mut file, bytes);
        // Closed before the rename (Windows cannot rename an open file).
        drop(file);
        if let Err(e) = filled {
            let _ = fs::remove_file(&temp);
            return Err(e);
        }
        if let Err(e) = fs::rename(&temp, &self.path) {
            let _ = fs::remove_file(&temp);
            return Err(io_err(&e));
        }
        self.emit(SaveStep::Renamed);
        self.sync_dir()?;
        if cfg!(unix) {
            self.emit(SaveStep::DirSynced);
        }
        Ok(())
    }

    /// Writes and syncs a temp file, then hard-links it to the vault path, which
    /// fails if anything is already there. The temp is removed in every branch.
    /// Where hard links are not supported (FAT, exFAT), falls back to an exclusive
    /// create of the vault path itself, removed again if writing it fails.
    fn create_new(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        if bytes.len() > MAX_FILE_LEN {
            return Err(StoreError::TooLarge);
        }
        // Anything at the path, even a dangling symlink, counts as existing.
        match fs::symlink_metadata(&self.path) {
            Ok(_) => return Err(StoreError::AlreadyExists),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(&e)),
        }
        self.check_dir()?;
        let temp = self.temp_path()?;
        let mut file = create_exclusive(&temp)?;
        let written = write_all_synced(&mut file, bytes);
        drop(file);
        if let Err(e) = written {
            let _ = fs::remove_file(&temp);
            return Err(e);
        }
        let linked = fs::hard_link(&temp, &self.path);
        // A temp that cannot be removed is harmless: it matches the temp pattern,
        // so the next unlock removes it.
        let _ = fs::remove_file(&temp);
        match linked {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                return Err(StoreError::AlreadyExists);
            }
            Err(_) => {
                // No hard links here. An exclusive create still never overwrites.
                let mut file = create_exclusive(&self.path)?;
                let written = write_all_synced(&mut file, bytes);
                drop(file);
                if let Err(e) = written {
                    // The file is ours (we just created it), and partly written.
                    let _ = fs::remove_file(&self.path);
                    return Err(e);
                }
            }
        }
        self.sync_dir()
    }

    fn remove_stale_temps(&mut self) -> Result<usize, StoreError> {
        let mut removed = 0usize;
        for entry in fs::read_dir(self.dir()).map_err(|e| io_err(&e))? {
            let entry = entry.map_err(|e| io_err(&e))?;
            if !self.is_own_temp_name(&entry.file_name()) {
                continue;
            }
            // `file_type` does not follow symlinks, so a symlink is never removed
            // and its target never touched.
            if !entry.file_type().map_err(|e| io_err(&e))?.is_file() {
                continue;
            }
            match fs::remove_file(entry.path()) {
                Ok(()) => removed = removed.saturating_add(1),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(io_err(&e)),
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_two_digits_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[test]
    fn temp_names_match_the_cleanup_pattern() {
        let s = FsStore::new("dir/holm.vault");
        let a = s.temp_path().unwrap();
        let b = s.temp_path().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.parent(), Some(Path::new("dir")));
        assert!(s.is_own_temp_name(a.file_name().unwrap()));
        assert!(!s.is_own_temp_name(OsStr::new("holm.vault")));
    }

    #[test]
    fn bare_file_name_uses_the_current_directory() {
        assert_eq!(FsStore::new("holm.vault").dir(), Path::new("."));
    }

    #[test]
    fn path_without_file_name_is_refused() {
        let s = FsStore::new("/");
        assert_eq!(
            s.temp_path().err(),
            Some(StoreError::Io(ErrorKind::InvalidInput))
        );
        assert!(!s.is_own_temp_name(OsStr::new(".tmp-0123456789abcdef")));
    }
}
