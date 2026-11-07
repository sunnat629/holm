//! Where the vault file lives: the [`VaultStore`] trait.
//!
//! The session reads and writes whole files through this trait and never touches the
//! file system itself. The real store (a file on disk, with durable writes) lives in
//! `holm-platform`; tests use an in-memory one. Every implementation must keep the
//! contract written on each method, because the session's safety depends on it: a
//! save that fails half way must never leave a damaged vault behind.

#[cfg(test)]
use crate::format::MAX_FILE_LEN;

/// Why a store operation failed. Carries no file contents and no path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// There is no vault file.
    #[error("no vault file was found")]
    NotFound,
    /// A file already exists where a new one was to be created.
    #[error("a file already exists there")]
    AlreadyExists,
    /// The file, or the bytes to write, are over the 64 MiB limit.
    #[error("the vault file is too large (64 MiB limit)")]
    TooLarge,
    /// The vault path is not a regular file (for example a symlink or a folder).
    #[error("the vault path is not a regular file")]
    NotARegularFile,
    /// The operating system reported an error of this kind.
    #[error("the vault file could not be read or written: {0}")]
    Io(std::io::ErrorKind),
}

/// Reads and writes the bytes of one vault file.
///
/// The doc comment on each method is part of the contract. An implementation that
/// cannot keep it must return an error instead.
pub trait VaultStore {
    /// Returns the whole file.
    ///
    /// A file longer than [`MAX_FILE_LEN`](crate::format::MAX_FILE_LEN) is refused
    /// with [`StoreError::TooLarge`] **before** any of it is read, so a huge file
    /// costs no memory.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if there is no file, [`StoreError::TooLarge`],
    /// [`StoreError::NotARegularFile`], or [`StoreError::Io`].
    fn read(&mut self) -> Result<Vec<u8>, StoreError>;

    /// Replaces the file with `bytes`, creating it if needed.
    ///
    /// Atomic against a crash at any point: afterwards the file holds either the old
    /// bytes or the new bytes in full, never a mix and never a truncated file. Bytes
    /// longer than [`MAX_FILE_LEN`](crate::format::MAX_FILE_LEN) are refused with
    /// [`StoreError::TooLarge`] before anything is written.
    ///
    /// # Errors
    /// [`StoreError::TooLarge`], [`StoreError::NotARegularFile`], or
    /// [`StoreError::Io`]. An error before the new bytes are in place leaves the old
    /// file unchanged. An error after that point (for example a failed directory
    /// sync after the rename in `holm-platform`) may leave the new bytes in full. So
    /// callers treat any `replace` error as "old or new": they keep their changes
    /// and stay dirty, and the next save writes them again.
    fn replace(&mut self, bytes: &[u8]) -> Result<(), StoreError>;

    /// Creates the file with `bytes`. Never overwrites: if a file already exists it
    /// is left untouched and [`StoreError::AlreadyExists`] is returned. Bytes longer
    /// than [`MAX_FILE_LEN`](crate::format::MAX_FILE_LEN) are refused with
    /// [`StoreError::TooLarge`]. The same crash rule as [`VaultStore::replace`]
    /// applies: no file, or the whole file.
    ///
    /// # Errors
    /// [`StoreError::AlreadyExists`], [`StoreError::TooLarge`], or
    /// [`StoreError::Io`].
    fn create_new(&mut self, bytes: &[u8]) -> Result<(), StoreError>;

    /// Removes temporary files left by an interrupted write, and returns how many it
    /// removed. Only files matching the store's own temp pattern are touched.
    ///
    /// # Errors
    /// [`StoreError::Io`] if a temp file could not be listed or removed.
    fn remove_stale_temps(&mut self) -> Result<usize, StoreError>;

    /// Keeps a byte-for-byte copy of a vault file beside the vault, named
    /// `<vault file name>.<tag>.bak`, for the migration backup (Phase B). The copy is
    /// created exclusively (never overwrites), owner-only where the system has modes,
    /// synced, and the directory synced. It is crash-atomic: afterwards there is no
    /// copy or the whole copy.
    ///
    /// If a copy with this tag already exists with the same bytes, this is `Ok`
    /// (a retry after a crash). If it holds other bytes, nothing is changed and the
    /// result is [`StoreError::AlreadyExists`]. A symlink or folder at the copy's
    /// path is [`StoreError::NotARegularFile`] and is never followed. `tag` must
    /// match `[a-z0-9-]{1,32}` ([`check_backup_tag`]) so it cannot form a path;
    /// anything else is `Io(InvalidInput)`.
    ///
    /// The default refuses with `Io(Unsupported)`: a store that cannot keep a copy
    /// must not let a migration start.
    ///
    /// # Errors
    /// [`StoreError::AlreadyExists`], [`StoreError::TooLarge`],
    /// [`StoreError::NotARegularFile`], or [`StoreError::Io`].
    fn keep_backup_copy(&mut self, tag: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let _ = (tag, bytes);
        Err(StoreError::Io(std::io::ErrorKind::Unsupported))
    }

    /// Removes the copy `<vault file name>.<tag>.bak` and syncs the directory. Only
    /// that one file, never following a symlink. A missing copy is
    /// [`StoreError::NotFound`]. The tag is checked as in
    /// [`VaultStore::keep_backup_copy`].
    ///
    /// # Errors
    /// [`StoreError::NotFound`], [`StoreError::NotARegularFile`], or
    /// [`StoreError::Io`].
    fn remove_backup_copy(&mut self, tag: &str) -> Result<(), StoreError> {
        let _ = tag;
        Err(StoreError::Io(std::io::ErrorKind::Unsupported))
    }

    /// False only if nothing is at `<vault file name>.<tag>.bak` (a real not-found).
    /// Anything else there, even a symlink or a folder, counts as present, so the
    /// session keeps its note; [`VaultStore::remove_backup_copy`] still refuses it.
    ///
    /// # Errors
    /// [`StoreError::Io`], including `InvalidInput` for a bad tag.
    fn backup_copy_exists(&self, tag: &str) -> Result<bool, StoreError> {
        let _ = tag;
        Err(StoreError::Io(std::io::ErrorKind::Unsupported))
    }
}

/// Longest backup tag.
pub const MAX_BACKUP_TAG_LEN: usize = 32;

/// Checks a backup tag: 1 to 32 characters from `a-z`, `0-9` and `-`, so it can
/// never hold a path separator or a dot.
///
/// # Errors
/// `Io(InvalidInput)` for any other tag.
pub fn check_backup_tag(tag: &str) -> Result<(), StoreError> {
    let ok = !tag.is_empty()
        && tag.len() <= MAX_BACKUP_TAG_LEN
        && tag
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(StoreError::Io(std::io::ErrorKind::InvalidInput))
    }
}

/// An in-memory store for tests. Writes are all-or-nothing by construction.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct MemStore {
    /// The file, or `None` if there is none.
    pub(crate) bytes: Option<Vec<u8>>,
    /// The next `replace` or `create_new` fails with this error and changes nothing.
    pub(crate) fail_next_write: Option<StoreError>,
    /// The next `replace` stores the new bytes in full and then fails with this
    /// error, like a directory sync that fails after the rename.
    pub(crate) fail_after_write: Option<StoreError>,
    /// Makes every `read` fail.
    pub(crate) fail_reads: bool,
    /// Sets [`MemStore::fail_reads`] when a `replace` fails, so the read-back after
    /// a failed write fails while the read before it worked.
    pub(crate) fail_reads_after_failed_replace: bool,
    /// Makes every `remove_stale_temps` fail.
    pub(crate) fail_temp_cleanup: bool,
    /// How many times `remove_stale_temps` was called.
    pub(crate) temp_cleanups: usize,
    /// Backup copies by tag.
    pub(crate) backups: std::collections::BTreeMap<String, Vec<u8>>,
    /// The next `keep_backup_copy` fails with this error and changes nothing.
    pub(crate) fail_backup_copy: Option<StoreError>,
    /// Makes `backup_copy_exists` fail with this error (it cannot tell).
    pub(crate) fail_backup_exists: Option<StoreError>,
    /// How many times `keep_backup_copy` was called.
    pub(crate) backup_calls: usize,
}

#[cfg(test)]
impl MemStore {
    /// Checks a write before it happens: the injected failure, then the size.
    fn check_write(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        if let Some(e) = self.fail_next_write.take() {
            return Err(e);
        }
        if bytes.len() > MAX_FILE_LEN {
            return Err(StoreError::TooLarge);
        }
        Ok(())
    }
}

#[cfg(test)]
impl VaultStore for MemStore {
    fn read(&mut self) -> Result<Vec<u8>, StoreError> {
        if self.fail_reads {
            return Err(StoreError::Io(std::io::ErrorKind::PermissionDenied));
        }
        let bytes = self.bytes.as_ref().ok_or(StoreError::NotFound)?;
        if bytes.len() > MAX_FILE_LEN {
            return Err(StoreError::TooLarge);
        }
        Ok(bytes.clone())
    }

    fn replace(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        let result = self.check_write(bytes).and_then(|()| {
            self.bytes = Some(bytes.to_vec());
            match self.fail_after_write.take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        });
        if result.is_err() && self.fail_reads_after_failed_replace {
            self.fail_reads = true;
        }
        result
    }

    fn create_new(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        if self.bytes.is_some() {
            return Err(StoreError::AlreadyExists);
        }
        self.check_write(bytes)?;
        self.bytes = Some(bytes.to_vec());
        Ok(())
    }

    fn remove_stale_temps(&mut self) -> Result<usize, StoreError> {
        self.temp_cleanups = self.temp_cleanups.saturating_add(1);
        if self.fail_temp_cleanup {
            return Err(StoreError::Io(std::io::ErrorKind::PermissionDenied));
        }
        Ok(0)
    }

    fn keep_backup_copy(&mut self, tag: &str, bytes: &[u8]) -> Result<(), StoreError> {
        check_backup_tag(tag)?;
        self.backup_calls = self.backup_calls.saturating_add(1);
        if let Some(e) = self.fail_backup_copy.take() {
            return Err(e);
        }
        if bytes.len() > MAX_FILE_LEN {
            return Err(StoreError::TooLarge);
        }
        match self.backups.get(tag) {
            Some(old) if old.as_slice() == bytes => Ok(()),
            Some(_) => Err(StoreError::AlreadyExists),
            None => {
                self.backups.insert(tag.to_owned(), bytes.to_vec());
                Ok(())
            }
        }
    }

    fn remove_backup_copy(&mut self, tag: &str) -> Result<(), StoreError> {
        check_backup_tag(tag)?;
        self.backups
            .remove(tag)
            .map(|_| ())
            .ok_or(StoreError::NotFound)
    }

    fn backup_copy_exists(&self, tag: &str) -> Result<bool, StoreError> {
        check_backup_tag(tag)?;
        if let Some(e) = &self.fail_backup_exists {
            return Err(*e);
        }
        Ok(self.backups.contains_key(tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_store_follows_the_contract() {
        let mut s = MemStore::default();
        assert_eq!(s.read(), Err(StoreError::NotFound));
        assert_eq!(s.create_new(b"one"), Ok(()));
        assert_eq!(s.create_new(b"two"), Err(StoreError::AlreadyExists));
        assert_eq!(s.read(), Ok(b"one".to_vec()));
        assert_eq!(s.replace(b"three"), Ok(()));
        assert_eq!(s.read(), Ok(b"three".to_vec()));
    }

    #[test]
    fn mem_store_failures_change_nothing() {
        let mut s = MemStore {
            bytes: Some(b"old".to_vec()),
            fail_next_write: Some(StoreError::Io(std::io::ErrorKind::StorageFull)),
            ..MemStore::default()
        };
        assert_eq!(
            s.replace(b"new"),
            Err(StoreError::Io(std::io::ErrorKind::StorageFull))
        );
        assert_eq!(s.read(), Ok(b"old".to_vec()));
        let big = vec![0u8; MAX_FILE_LEN + 1];
        assert_eq!(s.replace(&big), Err(StoreError::TooLarge));
        assert_eq!(s.read(), Ok(b"old".to_vec()));
        s.bytes = Some(big);
        assert_eq!(s.read(), Err(StoreError::TooLarge));
    }

    #[test]
    fn mem_store_can_fail_after_writing() {
        let mut s = MemStore {
            bytes: Some(b"old".to_vec()),
            fail_after_write: Some(StoreError::Io(std::io::ErrorKind::Other)),
            ..MemStore::default()
        };
        assert_eq!(
            s.replace(b"new"),
            Err(StoreError::Io(std::io::ErrorKind::Other))
        );
        assert_eq!(s.read(), Ok(b"new".to_vec()));
        assert_eq!(s.replace(b"newer"), Ok(()));
        s.fail_reads = true;
        assert_eq!(
            s.read(),
            Err(StoreError::Io(std::io::ErrorKind::PermissionDenied))
        );
    }

    #[test]
    fn store_errors_never_mention_a_password() {
        let all = [
            StoreError::NotFound,
            StoreError::AlreadyExists,
            StoreError::TooLarge,
            StoreError::NotARegularFile,
            StoreError::Io(std::io::ErrorKind::StorageFull),
        ];
        for e in all {
            assert!(!e.to_string().to_lowercase().contains("password"), "{e}");
        }
    }

    #[test]
    fn backup_tags_are_checked() {
        for ok in ["a", "v1-2026", "0", &"a".repeat(32)] {
            assert_eq!(check_backup_tag(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "A",
            "a.b",
            "a/b",
            "..",
            "a b",
            "a\\b",
            "é",
            &"a".repeat(33),
        ] {
            assert_eq!(
                check_backup_tag(bad),
                Err(StoreError::Io(std::io::ErrorKind::InvalidInput)),
                "{bad}"
            );
        }
    }

    #[test]
    fn mem_store_backup_copies() {
        let mut s = MemStore::default();
        assert_eq!(s.backup_copy_exists("t"), Ok(false));
        assert_eq!(s.remove_backup_copy("t"), Err(StoreError::NotFound));
        s.keep_backup_copy("t", b"one").unwrap();
        assert_eq!(s.keep_backup_copy("t", b"one"), Ok(()));
        assert_eq!(
            s.keep_backup_copy("t", b"two"),
            Err(StoreError::AlreadyExists)
        );
        assert_eq!(s.backups["t"], b"one");
        assert_eq!(s.backup_copy_exists("t"), Ok(true));
        s.fail_backup_copy = Some(StoreError::Io(std::io::ErrorKind::StorageFull));
        assert_eq!(
            s.keep_backup_copy("u", b"x"),
            Err(StoreError::Io(std::io::ErrorKind::StorageFull))
        );
        assert!(!s.backups.contains_key("u"));
        assert_eq!(
            s.keep_backup_copy("T", b"x").err(),
            Some(StoreError::Io(std::io::ErrorKind::InvalidInput))
        );
        s.remove_backup_copy("t").unwrap();
        assert_eq!(s.backup_copy_exists("t"), Ok(false));
    }
}
