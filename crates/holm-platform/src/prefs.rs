#![forbid(unsafe_code)]
//! Holm's device preferences: small settings that are not part of any vault.
//!
//! The vault's own security settings live inside its encrypted body (see
//! `holm_core::settings`). A preference here must work before a vault is unlocked, on
//! the unlock screen itself, so it cannot live there. The file is `holm-prefs`, next to
//! the vault file, owner-only (0600 on Unix). It holds no secret: one `key=value` line
//! per preference, and an unknown key is ignored.
//!
//! Loading never fails. A missing, unreadable, oversized or garbled file gives the
//! defaults, so a bad file can never stop Holm from opening. Saving writes a temporary
//! file and renames it over the old one, so a crash leaves either the old file or the
//! new one.

use std::fs;
use std::path::{Path, PathBuf};

use holm_core::store::StoreError;

use crate::private_file::{read_capped, write_new_private_file};

/// The preferences file's name, in the same folder as the vault file.
pub const PREFS_FILE_NAME: &str = "holm-prefs";

/// A preferences file larger than this is ignored (the real one is a few dozen bytes).
const MAX_PREFS_BYTES: usize = 4096;

/// The key for [`Prefs::hide_from_capture`].
const HIDE_KEY: &str = "hide_from_capture";

/// Device preferences. [`Prefs::default`] is every preference at its default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Prefs {
    /// Ask the OS to keep Holm's windows out of screenshots and screen sharing.
    /// Off by default.
    pub hide_from_capture: bool,
}

impl Prefs {
    /// The file's text.
    fn to_text(self) -> String {
        format!(
            "{HIDE_KEY}={}\n",
            if self.hide_from_capture { "on" } else { "off" }
        )
    }

    /// Reads the text leniently: only the exact value `on` turns a preference on.
    fn from_text(text: &str) -> Prefs {
        let mut prefs = Prefs::default();
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=')
                && key.trim() == HIDE_KEY
            {
                prefs.hide_from_capture = value.trim() == "on";
            }
        }
        prefs
    }
}

/// Where the preferences for the vault at `vault_path` are kept: `holm-prefs` in the
/// vault's folder.
#[must_use]
pub fn prefs_path(vault_path: &Path) -> PathBuf {
    vault_path.with_file_name(PREFS_FILE_NAME)
}

/// The saved preferences for the vault at `vault_path`, or the defaults when there is
/// no usable file. Never fails.
#[must_use]
pub fn load(vault_path: &Path) -> Prefs {
    match read_capped(&prefs_path(vault_path), MAX_PREFS_BYTES) {
        Ok(bytes) => {
            std::str::from_utf8(&bytes).map_or_else(|_| Prefs::default(), Prefs::from_text)
        }
        Err(_) => Prefs::default(),
    }
}

/// Saves `prefs` for the vault at `vault_path`, replacing the old file.
///
/// # Errors
/// [`StoreError::Io`] (or the other [`StoreError`] kinds the private-file writer
/// returns) if the file cannot be written or renamed. The old file is then unchanged.
pub fn save(vault_path: &Path, prefs: Prefs) -> Result<(), StoreError> {
    let path = prefs_path(vault_path);
    let temp = path.with_file_name(format!("{PREFS_FILE_NAME}.tmp"));
    // A leftover temp file from a crash would make the create-new write fail.
    match fs::remove_file(&temp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(StoreError::Io(e.kind())),
    }
    write_new_private_file(&temp, prefs.to_text().as_bytes())?;
    fs::rename(&temp, &path).map_err(|e| {
        let _ = fs::remove_file(&temp);
        StoreError::Io(e.kind())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_in(dir: &Path) -> PathBuf {
        dir.join("holm.vault")
    }

    #[test]
    fn default_is_off() {
        assert!(!Prefs::default().hide_from_capture);
    }

    #[test]
    fn missing_file_gives_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(&vault_in(dir.path())), Prefs::default());
    }

    #[test]
    fn setting_round_trips_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(dir.path());
        save(
            &vault,
            Prefs {
                hide_from_capture: true,
            },
        )
        .unwrap();
        assert!(load(&vault).hide_from_capture);
        save(
            &vault,
            Prefs {
                hide_from_capture: false,
            },
        )
        .unwrap();
        assert!(!load(&vault).hide_from_capture);
        assert!(!dir.path().join("holm-prefs.tmp").exists());
    }

    #[test]
    fn a_stale_temp_file_does_not_block_a_save() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(dir.path());
        fs::write(dir.path().join("holm-prefs.tmp"), b"junk").unwrap();
        save(
            &vault,
            Prefs {
                hide_from_capture: true,
            },
        )
        .unwrap();
        assert!(load(&vault).hide_from_capture);
    }

    #[test]
    fn garbage_oversized_and_unknown_content_mean_off() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(dir.path());
        let path = prefs_path(&vault);
        for bytes in [
            b"\xff\xfe\x00".to_vec(),
            b"hide_from_capture=maybe\n".to_vec(),
            b"hide_from_capture=1\n".to_vec(),
            b"other=on\n".to_vec(),
            vec![b'x'; MAX_PREFS_BYTES + 1],
        ] {
            fs::write(&path, bytes).unwrap();
            assert!(!load(&vault).hide_from_capture);
        }
    }

    #[test]
    fn only_the_exact_value_on_turns_it_on() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(dir.path());
        fs::write(prefs_path(&vault), "future=1\nhide_from_capture=on\n").unwrap();
        assert!(load(&vault).hide_from_capture);
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(dir.path());
        save(&vault, Prefs::default()).unwrap();
        let mode = fs::metadata(prefs_path(&vault))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
