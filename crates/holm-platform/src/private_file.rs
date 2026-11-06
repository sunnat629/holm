#![forbid(unsafe_code)]
//! Plaintext files the user asked for: the export file and the import file.
//!
//! [`write_new_private_file`] creates a new file that only its owner can read (mode
//! 0600 on Unix) and never touches an existing file or follows a symlink. If anything
//! fails after the create, truncation, sync and removal are all best effort. A
//! failed cleanup may leave plaintext. APFS may keep freed blocks or snapshots
//! even after successful cleanup; this is not secure erasure.
//!
//! [`read_capped`] reads a whole import file into wiping memory, but only a regular
//! file no larger than the caller's cap. A FIFO, a device or a folder is refused
//! without blocking, and a file that grows or shrinks while it is read is refused
//! too, so the bytes parsed are exactly the bytes whose size was checked.
//!
//! Errors carry a [`StoreError`] kind only, never a path or any file content.

use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;

use holm_core::store::StoreError;
use zeroize::Zeroizing;

use crate::fs_store::{create_exclusive, open_for_read};

/// Creates an owner-only file, syncs its data, then syncs its parent on Unix.
///
/// # Errors
/// [`StoreError::AlreadyExists`] if anything (a file, a folder or a symlink, even a
/// dangling one) is already at `path`; it is left untouched. [`StoreError::Io`] for
/// any other failure, after best-effort cleanup of the new file.
pub fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    write_new_private_file_with(path, bytes, &mut |file, b| file.write_all(b))
}

/// [`write_new_private_file`] with the write step passed in, so a test can make it
/// fail halfway.
pub(crate) fn write_new_private_file_with(
    path: &Path,
    bytes: &[u8],
    write: &mut dyn FnMut(&mut File, &[u8]) -> io::Result<()>,
) -> Result<(), StoreError> {
    write_new_private_file_with_sync(path, bytes, write, &mut |file| file.sync_all())
}

/// A sync seam that lets tests distinguish the file from its parent.
fn write_new_private_file_with_sync(
    path: &Path,
    bytes: &[u8],
    write: &mut dyn FnMut(&mut File, &[u8]) -> io::Result<()>,
    sync: &mut dyn FnMut(&File) -> io::Result<()>,
) -> Result<(), StoreError> {
    let mut file = create_exclusive(path)?;
    let written = write(&mut file, bytes)
        .and_then(|()| sync(&file))
        .and_then(|()| sync_parent(path, sync));
    match written {
        Ok(()) => Ok(()),
        Err(e) => {
            // First empty the file through the handle, so if the remove below fails
            // too, less plaintext may remain. Every cleanup step is best effort;
            // report the original write or sync error.
            let _ = file.set_len(0);
            let _ = file.sync_all();
            drop(file);
            // Only a file this call created is ever at `path` here, unless something
            // replaced it meanwhile.
            let _ = fs::remove_file(path);
            Err(StoreError::Io(e.kind()))
        }
    }
}

/// Uses the vault store's rule for volumes that cannot sync directories.
fn sync_parent(path: &Path, sync: &mut dyn FnMut(&File) -> io::Result<()>) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        let dir = File::open(parent.unwrap_or(Path::new(".")))?;
        match sync(&dir) {
            Ok(()) => {}
            Err(e) if crate::fs_store::dir_sync_unsupported(&e) => {}
            Err(e) => return Err(e),
        }
    }
    #[cfg(not(unix))]
    let _ = (path, sync);
    Ok(())
}

/// Reads all of `path` if it is a regular file (after following symlinks) of at most
/// `max` bytes.
///
/// # Errors
/// [`StoreError::TooLarge`] over `max`, [`StoreError::NotARegularFile`] for a folder,
/// FIFO, device or socket, and [`StoreError::Io`] for anything else, including a
/// missing file (`ErrorKind::NotFound`) and a file whose size changed while it was
/// read (`ErrorKind::InvalidData` or `ErrorKind::UnexpectedEof`).
pub fn read_capped(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    read_capped_with(path, max, |file| file)
}

/// [`read_capped`] with the opened file wrapped by `wrap` before it is read, so a test
/// can make the file look as if it grew or shrank after the size check.
pub(crate) fn read_capped_with<R: Read>(
    path: &Path,
    max: usize,
    wrap: impl FnOnce(File) -> R,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    // Checked before the open, so a FIFO or device is never opened at all.
    let len = checked_len(&fs::metadata(path).map_err(io_err)?, max)?;
    // Non-blocking on Unix, so a FIFO swapped in after that check cannot hang the open,
    // and checked again on the handle that is really read.
    let file = open_for_read(path).map_err(io_err)?;
    let len_now = checked_len(&file.metadata().map_err(io_err)?, max)?;
    if len_now != len {
        return Err(StoreError::Io(ErrorKind::InvalidData));
    }
    let mut reader = wrap(file);
    let mut bytes = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut bytes).map_err(io_err)?;
    // The file must end where its size said: one more byte means it grew.
    let mut probe = [0u8; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => return Ok(bytes),
            Ok(_) => return Err(StoreError::Io(ErrorKind::InvalidData)),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(io_err(e)),
        }
    }
}

/// The size of a regular file of at most `max` bytes.
fn checked_len(meta: &fs::Metadata, max: usize) -> Result<usize, StoreError> {
    if !meta.is_file() {
        return Err(StoreError::NotARegularFile);
    }
    match usize::try_from(meta.len()) {
        Ok(len) if len <= max => Ok(len),
        _ => Err(StoreError::TooLarge),
    }
}

fn io_err(e: io::Error) -> StoreError {
    StoreError::Io(e.kind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn kind(e: StoreError) -> Option<ErrorKind> {
        match e {
            StoreError::Io(k) => Some(k),
            _ => None,
        }
    }

    #[test]
    fn write_new_private_file_writes_and_syncs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        write_new_private_file(&path, b"\"a\",\"b\"\r\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"\"a\",\"b\"\r\n");
    }

    #[cfg(unix)]
    #[test]
    fn write_new_private_file_syncs_parent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        let mut synced_dirs = Vec::new();
        write_new_private_file_with_sync(
            &path,
            b"example",
            &mut |file, bytes| file.write_all(bytes),
            &mut |file| {
                synced_dirs.push(file.metadata()?.is_dir());
                file.sync_all()
            },
        )
        .unwrap();
        assert_eq!(synced_dirs, [false, true]);
    }

    #[cfg(unix)]
    #[test]
    fn parent_sync_failure_removes_export() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        let result = write_new_private_file_with_sync(
            &path,
            b"example",
            &mut |file, bytes| file.write_all(bytes),
            &mut |file| {
                if file.metadata()?.is_dir() {
                    Err(io::Error::from(ErrorKind::PermissionDenied))
                } else {
                    file.sync_all()
                }
            },
        );
        assert_eq!(result, Err(StoreError::Io(ErrorKind::PermissionDenied)));
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn only_directory_sync_may_be_unsupported() {
        for fail_directory in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("export.csv");
            let result = write_new_private_file_with_sync(
                &path,
                b"example",
                &mut |file, bytes| file.write_all(bytes),
                &mut |file| {
                    if file.metadata()?.is_dir() == fail_directory {
                        Err(io::Error::from(ErrorKind::Unsupported))
                    } else {
                        file.sync_all()
                    }
                },
            );
            if fail_directory {
                assert_eq!(result, Ok(()));
                assert!(path.exists());
            } else {
                assert_eq!(result, Err(StoreError::Io(ErrorKind::Unsupported)));
                assert!(!path.exists());
            }
        }
    }

    #[test]
    fn write_new_private_file_refuses_existing_and_symlink() {
        let dir = tempfile::tempdir().unwrap();

        let existing = dir.path().join("existing.csv");
        fs::write(&existing, b"keep me").unwrap();
        assert_eq!(
            write_new_private_file(&existing, b"EXAMPLE"),
            Err(StoreError::AlreadyExists)
        );
        assert_eq!(fs::read(&existing).unwrap(), b"keep me");

        let folder = dir.path().join("folder");
        fs::create_dir(&folder).unwrap();
        assert_eq!(
            write_new_private_file(&folder, b"EXAMPLE"),
            Err(StoreError::AlreadyExists)
        );
        assert!(folder.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let missing = dir.path().join("missing-target.csv");
            let dangling = dir.path().join("dangling.csv");
            symlink(&missing, &dangling).unwrap();
            assert_eq!(
                write_new_private_file(&dangling, b"EXAMPLE"),
                Err(StoreError::AlreadyExists)
            );
            assert!(
                fs::symlink_metadata(&missing).is_err(),
                "target was created"
            );

            let to_file = dir.path().join("to-file.csv");
            symlink(&existing, &to_file).unwrap();
            assert_eq!(
                write_new_private_file(&to_file, b"EXAMPLE"),
                Err(StoreError::AlreadyExists)
            );
            assert_eq!(fs::read(&existing).unwrap(), b"keep me");
            assert!(
                fs::symlink_metadata(&to_file)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn write_new_private_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        write_new_private_file(&path, b"EXAMPLE").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn failed_write_removes_partial_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        let mut fail_halfway = |file: &mut File, bytes: &[u8]| {
            file.write_all(&bytes[..3])?;
            Err(io::Error::from(ErrorKind::StorageFull))
        };
        let err =
            write_new_private_file_with(&path, b"EXAMPLE-secret", &mut fail_halfway).unwrap_err();
        assert_eq!(err, StoreError::Io(ErrorKind::StorageFull));
        assert!(fs::symlink_metadata(&path).is_err(), "partial file left");
    }

    /// The remove can fail too (here the folder turns read-only mid-write). The
    /// partial file is then left, but empty: it was truncated and synced first.
    #[cfg(unix)]
    #[test]
    fn failed_write_truncates_before_a_failed_remove() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        let folder = dir.path().to_owned();
        let set_mode = |m: u32| fs::set_permissions(&folder, fs::Permissions::from_mode(m));
        let mut fail_halfway = |file: &mut File, bytes: &[u8]| {
            file.write_all(&bytes[..7])?;
            file.sync_all()?;
            set_mode(0o500)?;
            Err(io::Error::from(ErrorKind::StorageFull))
        };
        let err =
            write_new_private_file_with(&path, b"EXAMPLE-secret", &mut fail_halfway).unwrap_err();
        set_mode(0o700).unwrap();
        assert_eq!(err, StoreError::Io(ErrorKind::StorageFull));
        // As root the remove still works and the file is gone; that is fine too.
        if let Ok(meta) = fs::symlink_metadata(&path) {
            assert_eq!(meta.len(), 0, "partial plaintext left on disk");
            assert_eq!(fs::read(&path).unwrap(), b"");
        }
    }

    #[test]
    fn read_capped_reads_up_to_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("import.csv");
        fs::write(&path, b"0123456789").unwrap();
        assert_eq!(read_capped(&path, 10).unwrap().as_slice(), b"0123456789");
        assert_eq!(read_capped(&path, 9).map(|_| ()), Err(StoreError::TooLarge));

        let empty = dir.path().join("empty.csv");
        fs::write(&empty, b"").unwrap();
        assert!(read_capped(&empty, 0).unwrap().is_empty());

        let missing = dir.path().join("missing.csv");
        assert_eq!(
            read_capped(&missing, 10).map(|_| ()),
            Err(StoreError::Io(ErrorKind::NotFound))
        );

        #[cfg(unix)]
        {
            let link = dir.path().join("link.csv");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert_eq!(read_capped(&link, 10).unwrap().as_slice(), b"0123456789");
        }
    }

    #[test]
    fn read_capped_refuses_fifo_dir_and_oversize() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read_capped(dir.path(), 1 << 20).map(|_| ()),
            Err(StoreError::NotARegularFile)
        );

        let max = 64;
        let big = dir.path().join("big.csv");
        fs::write(&big, vec![b'x'; max + 1]).unwrap();
        assert_eq!(
            read_capped(&big, max).map(|_| ()),
            Err(StoreError::TooLarge)
        );

        #[cfg(unix)]
        {
            let fifo = dir.path().join("fifo.csv");
            crate::test_support::make_fifo(&fifo);
            let (tx, rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let _ = tx.send(read_capped(&fifo, max).map(|_| ()));
            });
            let got = rx
                .recv_timeout(Duration::from_secs(1))
                .expect("reading a FIFO blocked");
            assert_eq!(got, Err(StoreError::NotARegularFile));
            worker.join().unwrap();
        }
    }

    #[test]
    fn read_capped_refuses_growing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("import.csv");
        fs::write(&path, b"EXAMPLE").unwrap();

        let grew = read_capped_with(&path, 64, |f| f.chain(&b"!"[..])).map(|_| ());
        assert_eq!(grew.map_err(kind), Err(Some(ErrorKind::InvalidData)));

        let shrank = read_capped_with(&path, 64, |f| f.take(3)).map(|_| ());
        assert_eq!(shrank.map_err(kind), Err(Some(ErrorKind::UnexpectedEof)));

        // A file really appended to after it was read is fine: it was read in full.
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"+")
            .unwrap();
        assert_eq!(read_capped(&path, 64).unwrap().as_slice(), b"EXAMPLE+");
    }
}
