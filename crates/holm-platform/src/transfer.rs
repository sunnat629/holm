#![forbid(unsafe_code)]
//! One import and export flow for the CLI and the GUI.
//!
//! Both front ends read an import file, refuse an export path that is taken, write
//! the plain export and write the encrypted backup through the functions here, so the
//! rules (absolute typed paths, the size cap, the file mode, the order of checks) live
//! in one place.
//!
//! [`TransferError`] holds no path and no file content, only which step failed. That
//! keeps every `Debug` and `Display` of it safe to log or show.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use holm_core::error::CoreError;
use holm_core::import::{ImportBatch, ImportError, ImportFormat, MAX_IMPORT_BYTES, parse};
use holm_core::session::Session;
use holm_core::store::{StoreError, VaultStore};
use holm_crypto::MasterPassword;

use crate::fs_store::FsStore;
use crate::private_file::{read_capped, write_new_private_file};

/// Why an import or export step failed. It holds no path and no content.
#[derive(Debug, PartialEq, Eq)]
pub enum TransferError {
    /// The import file is not there.
    NotFound,
    /// Something is already at the export path. It was not changed.
    Exists,
    /// The typed path is empty or does not start at the top folder of the disk.
    NotAbsolute,
    /// The import file could not be read.
    ReadFailed,
    /// The export file could not be written.
    WriteFailed,
    /// The import file is over the size cap.
    TooLarge,
    /// The file was read but is not a valid import.
    Import(ImportError),
    /// The vault session refused: wrong password, throttle, locked and so on.
    Core(CoreError),
}

/// Turns typed text into an absolute path, exactly as typed. Spaces are kept, because
/// a file name may begin or end with one.
///
/// # Errors
/// [`TransferError::NotAbsolute`] if the text is empty or not an absolute path.
pub fn typed_path(text: &str) -> Result<PathBuf, TransferError> {
    let path = Path::new(text);
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Err(TransferError::NotAbsolute)
    }
}

/// The format to read: `forced` if given, else JSON for a `.json` extension (any
/// case) and CSV for everything else.
#[must_use]
pub fn format_for(path: &Path, forced: Option<ImportFormat>) -> ImportFormat {
    if let Some(format) = forced {
        return format;
    }
    let is_json = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"));
    if is_json {
        ImportFormat::Json
    } else {
        ImportFormat::Csv
    }
}

/// Reads and parses an import file.
///
/// # Errors
/// [`TransferError::NotFound`], [`TransferError::TooLarge`],
/// [`TransferError::ReadFailed`] or [`TransferError::Import`].
pub fn read_import(
    path: &Path,
    forced: Option<ImportFormat>,
) -> Result<ImportBatch, TransferError> {
    let bytes = read_capped(path, MAX_IMPORT_BYTES).map_err(|e| match e {
        StoreError::NotFound | StoreError::Io(ErrorKind::NotFound) => TransferError::NotFound,
        StoreError::TooLarge => TransferError::TooLarge,
        _ => TransferError::ReadFailed,
    })?;
    parse(&bytes, format_for(path, forced)).map_err(TransferError::Import)
}

/// Refuses an export path that already has anything on it, a dangling symlink
/// included (`symlink_metadata` does not follow links).
///
/// # Errors
/// [`TransferError::Exists`], or [`TransferError::WriteFailed`] if the check itself
/// fails.
pub fn refuse_existing(dest: &Path) -> Result<(), TransferError> {
    match fs::symlink_metadata(dest) {
        Ok(_) => Err(TransferError::Exists),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(TransferError::WriteFailed),
    }
}

/// Writes every active item as an unencrypted CSV file at `dest` (mode 0600) and
/// returns how many items it holds. The path is checked first, so a taken path
/// never costs a password attempt.
///
/// # Errors
/// [`TransferError::Exists`], [`TransferError::Core`] (wrong password, throttled,
/// locked) or [`TransferError::WriteFailed`].
pub fn export_plain<S: VaultStore>(
    session: &mut Session<S>,
    password: &MasterPassword,
    dest: &Path,
) -> Result<usize, TransferError> {
    refuse_existing(dest)?;
    let csv = session.export_csv(password).map_err(TransferError::Core)?;
    let count = session.active_items().map_err(TransferError::Core)?.count();
    write_new_private_file(dest, csv.expose()).map_err(|e| match e {
        StoreError::AlreadyExists => TransferError::Exists,
        _ => TransferError::WriteFailed,
    })?;
    Ok(count)
}

/// Writes an encrypted backup at `dest`. It opens with the same master password.
///
/// # Errors
/// [`TransferError::Exists`] or [`TransferError::Core`].
pub fn export_backup<S: VaultStore>(
    session: &mut Session<S>,
    dest: &Path,
) -> Result<(), TransferError> {
    refuse_existing(dest)?;
    session
        .save_backup(&mut FsStore::new(dest))
        .map_err(|e| match e {
            CoreError::VaultExists | CoreError::Store(StoreError::AlreadyExists) => {
                TransferError::Exists
            }
            other => TransferError::Core(other),
        })
}

#[cfg(test)]
mod tests {
    use holm_core::clock::SystemClock;
    use holm_crypto::kdf::KdfParams;

    use super::*;

    const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";

    fn pw() -> MasterPassword {
        MasterPassword::new(PW.into())
    }

    fn new_session(path: &Path) -> Session<FsStore> {
        let mut s = Session::new(FsStore::new(path), Box::new(SystemClock::new()));
        s.create(&pw(), &KdfParams::FLOOR).unwrap();
        s
    }

    #[test]
    fn typed_path_must_be_absolute() {
        assert_eq!(typed_path("x.csv"), Err(TransferError::NotAbsolute));
        assert_eq!(typed_path(""), Err(TransferError::NotAbsolute));
        assert_eq!(typed_path("/tmp/x.csv"), Ok(PathBuf::from("/tmp/x.csv")));
    }

    #[test]
    fn typed_path_is_not_trimmed() {
        let p = typed_path("/tmp/x.csv ").unwrap();
        assert!(p.to_str().unwrap().ends_with("x.csv "));
    }

    #[test]
    fn format_by_extension() {
        assert_eq!(format_for(Path::new("a.JSON"), None), ImportFormat::Json);
        assert_eq!(format_for(Path::new("a.txt"), None), ImportFormat::Csv);
        assert_eq!(format_for(Path::new("a"), None), ImportFormat::Csv);
        assert_eq!(
            format_for(Path::new("a.json"), Some(ImportFormat::Csv)),
            ImportFormat::Csv
        );
    }

    #[test]
    fn export_refuses_existing_before_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_session(&dir.path().join("v.vault"));
        let dest = dir.path().join("out.csv");
        fs::write(&dest, b"keep").unwrap();
        let wrong = MasterPassword::new("not-the-password-at-all-EXAMPLE".into());
        assert_eq!(
            export_plain(&mut s, &wrong, &dest),
            Err(TransferError::Exists)
        );
        assert_eq!(s.throttle_status().consecutive_failures, 0);
        assert_eq!(fs::read(&dest).unwrap(), b"keep");
    }

    #[test]
    fn export_plain_writes_file_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_session(&dir.path().join("v.vault"));
        let dest = dir.path().join("out.csv");
        assert_eq!(export_plain(&mut s, &pw(), &dest), Ok(0));
        assert!(dest.exists());
    }

    #[test]
    fn backup_opens_with_same_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_session(&dir.path().join("v.vault"));
        let dest = dir.path().join("b.vault");
        export_backup(&mut s, &dest).unwrap();
        let mut b = Session::new(FsStore::new(&dest), Box::new(SystemClock::new()));
        b.unlock(&pw()).unwrap();
        assert_eq!(export_backup(&mut s, &dest), Err(TransferError::Exists));
    }

    #[test]
    fn errors_hold_no_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_session(&dir.path().join("EXAMPLE.vault"));
        let dest = dir.path().join("EXAMPLE-out.csv");
        let missing = dir.path().join("EXAMPLE-missing.csv");
        let errors = [
            read_import(&missing, None).unwrap_err(),
            typed_path("EXAMPLE").unwrap_err(),
            {
                fs::write(&dest, b"x").unwrap();
                export_backup(&mut s, &dest).unwrap_err()
            },
        ];
        for e in errors {
            assert!(!format!("{e:?}").contains("EXAMPLE"));
        }
    }
}
