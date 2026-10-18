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
    /// Makes every `remove_stale_temps` fail.
    pub(crate) fail_temp_cleanup: bool,
    /// How many times `remove_stale_temps` was called.
    pub(crate) temp_cleanups: usize,
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
        self.check_write(bytes)?;
        self.bytes = Some(bytes.to_vec());
        match self.fail_after_write.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
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
}
