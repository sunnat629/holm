//! Where the vault lives by default, and the folder that holds it.
//!
//! On macOS the vault is `~/Library/Application Support/Holm/holm.vault` (spec §8.0).
//! Other operating systems have no default path in Phase 3: the GUI runs on macOS only.
//!
//! Rules kept here:
//! - the home directory comes from `HOME` and must be an absolute path, never a
//!   relative or empty one (which would put the vault under the current directory);
//! - [`ensure_vault_dir`] creates only the last folder (`Holm`), owner-only (0700 on
//!   Unix), never a whole chain of parents;
//! - an existing folder must be a real directory (a symlink is refused, never
//!   followed) and, on Unix, must not be group or world writable; Holm never
//!   changes its mode;
//! - errors carry the [`std::io::ErrorKind`] only, never a path.

use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use holm_core::store::StoreError;

/// The folder under `~/Library/Application Support` that holds Holm's files.
pub const APP_DIR_NAME: &str = "Holm";

/// The vault's file name inside [`APP_DIR_NAME`].
pub const VAULT_FILE_NAME: &str = "holm.vault";

/// The default vault path under the home directory `home`:
/// `<home>/Library/Application Support/Holm/holm.vault`.
#[must_use]
pub fn vault_path_under(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join(APP_DIR_NAME)
        .join(VAULT_FILE_NAME)
}

/// The default vault path for this user, or `None` if there is none.
///
/// On macOS it is [`vault_path_under`] the `HOME` directory; `None` if `HOME` is
/// unset, empty or not an absolute path. Every other OS returns `None` in Phase 3.
#[must_use]
pub fn default_vault_path() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        from_home(std::env::var_os("HOME"))
    } else {
        None
    }
}

/// [`vault_path_under`] `home`, or `None` if `home` is missing, empty or relative.
fn from_home(home: Option<OsString>) -> Option<PathBuf> {
    let home = PathBuf::from(home?);
    if home.as_os_str().is_empty() || !home.is_absolute() {
        return None;
    }
    Some(vault_path_under(&home))
}

/// Makes sure the folder that holds `vault_path` exists and is safe to use.
///
/// A missing folder is created on its own (its parent must already exist), with mode
/// 0700 on Unix. An existing one must be a real directory, and on Unix none of the
/// group or world write bits (`0o022`) may be set; Holm never changes its mode.
/// Calling this again on a good folder is fine.
///
/// # Errors
/// - [`StoreError::NotARegularFile`] if the folder's name is taken by something that
///   is not a directory, such as a symlink (never followed) or a file;
/// - [`StoreError::Io`] with [`ErrorKind::PermissionDenied`] if the folder is group
///   or world writable (Unix);
/// - [`StoreError::Io`] with [`ErrorKind::NotFound`] if the folder's parent is
///   missing;
/// - [`StoreError::Io`] with [`ErrorKind::InvalidInput`] if `vault_path` has no
///   parent folder;
/// - [`StoreError::Io`] with the OS error's kind for any other failure.
pub fn ensure_vault_dir(vault_path: &Path) -> Result<(), StoreError> {
    let dir = match vault_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => return Err(StoreError::Io(ErrorKind::InvalidInput)),
    };
    match fs::symlink_metadata(dir) {
        Ok(meta) => check_existing_dir(&meta),
        Err(e) if e.kind() == ErrorKind::NotFound => match create_owner_only_dir(dir) {
            Ok(()) => Ok(()),
            // Something appeared between the check and the create: check it instead.
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let meta = fs::symlink_metadata(dir).map_err(|e| StoreError::Io(e.kind()))?;
                check_existing_dir(&meta)
            }
            Err(e) => Err(StoreError::Io(e.kind())),
        },
        Err(e) => Err(StoreError::Io(e.kind())),
    }
}

/// Accepts a real directory that is not group or world writable (Unix).
fn check_existing_dir(meta: &fs::Metadata) -> Result<(), StoreError> {
    if !meta.file_type().is_dir() {
        return Err(StoreError::NotARegularFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o022 != 0 {
            return Err(StoreError::Io(ErrorKind::PermissionDenied));
        }
    }
    Ok(())
}

/// Creates `dir` only (not its parents), mode 0700 on Unix.
fn create_owner_only_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_path_under_is_app_support() {
        assert_eq!(
            vault_path_under(Path::new("/Users/example")),
            PathBuf::from("/Users/example/Library/Application Support/Holm/holm.vault")
        );
    }

    #[test]
    fn relative_or_empty_home_is_none() {
        assert_eq!(from_home(None), None);
        assert_eq!(from_home(Some(OsString::new())), None);
        assert_eq!(from_home(Some(OsString::from("relative/home"))), None);
        assert_eq!(from_home(Some(OsString::from("."))), None);
        let home = if cfg!(windows) {
            "C:\\Users\\example"
        } else {
            "/Users/example"
        };
        assert_eq!(
            from_home(Some(OsString::from(home))),
            Some(vault_path_under(Path::new(home)))
        );
    }

    #[test]
    fn default_path_is_macos_only() {
        if !cfg!(target_os = "macos") {
            assert_eq!(default_vault_path(), None);
        }
    }

    #[test]
    fn path_without_parent_is_invalid_input() {
        assert_eq!(
            ensure_vault_dir(Path::new("holm.vault")),
            Err(StoreError::Io(ErrorKind::InvalidInput))
        );
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn mode(path: &Path) -> u32 {
            fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
        }

        #[test]
        fn vault_dir_is_owner_only() {
            let parent = tempfile::tempdir().unwrap();
            let vault = parent.path().join(APP_DIR_NAME).join(VAULT_FILE_NAME);
            ensure_vault_dir(&vault).unwrap();
            assert_eq!(mode(&parent.path().join(APP_DIR_NAME)), 0o700);
            assert_eq!(ensure_vault_dir(&vault), Ok(()), "a second call is fine");
            assert!(!vault.exists(), "no vault file is created");
        }

        #[test]
        fn vault_dir_symlink_refused() {
            let parent = tempfile::tempdir().unwrap();
            let target = parent.path().join("elsewhere");
            fs::create_dir(&target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
            let link = parent.path().join(APP_DIR_NAME);
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert_eq!(
                ensure_vault_dir(&link.join(VAULT_FILE_NAME)),
                Err(StoreError::NotARegularFile)
            );
            assert!(
                fs::symlink_metadata(&link)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the link is left alone"
            );
            assert_eq!(mode(&target), 0o700, "the target is untouched");
            assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        }

        #[test]
        fn plain_file_in_place_of_dir_refused() {
            let parent = tempfile::tempdir().unwrap();
            let file = parent.path().join(APP_DIR_NAME);
            fs::write(&file, b"").unwrap();
            assert_eq!(
                ensure_vault_dir(&file.join(VAULT_FILE_NAME)),
                Err(StoreError::NotARegularFile)
            );
        }

        #[test]
        fn missing_parent_is_not_found() {
            let parent = tempfile::tempdir().unwrap();
            let vault = parent
                .path()
                .join("missing")
                .join(APP_DIR_NAME)
                .join(VAULT_FILE_NAME);
            assert_eq!(
                ensure_vault_dir(&vault),
                Err(StoreError::Io(ErrorKind::NotFound))
            );
            assert!(!parent.path().join("missing").exists(), "not recursive");
        }

        #[test]
        fn world_writable_dir_refused() {
            let parent = tempfile::tempdir().unwrap();
            let dir = parent.path().join(APP_DIR_NAME);
            let vault = dir.join(VAULT_FILE_NAME);
            fs::create_dir(&dir).unwrap();
            for (bits, expected) in [
                (0o777, Err(StoreError::Io(ErrorKind::PermissionDenied))),
                (0o775, Err(StoreError::Io(ErrorKind::PermissionDenied))),
                (0o757, Err(StoreError::Io(ErrorKind::PermissionDenied))),
                (0o755, Ok(())),
            ] {
                fs::set_permissions(&dir, fs::Permissions::from_mode(bits)).unwrap();
                assert_eq!(ensure_vault_dir(&vault), expected, "{bits:o}");
                assert_eq!(mode(&dir), bits, "mode is never changed ({bits:o})");
            }
        }
    }
}
