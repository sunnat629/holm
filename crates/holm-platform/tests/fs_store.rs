//! `FsStore` against real files, each test in its own temporary directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use holm_core::format::MAX_FILE_LEN;
use holm_core::store::{StoreError, VaultStore};
use holm_platform::fs_store::{FsStore, SaveStep};

/// Names in `dir` that look like a temp file (`*.tmp-*`).
fn temps(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp-"))
        .collect();
    out.sort();
    out
}

fn vault_in(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("holm.vault")
}

#[test]
fn create_new_then_read() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = FsStore::new(vault_in(&dir));
    assert_eq!(s.path(), vault_in(&dir));
    assert_eq!(s.read(), Err(StoreError::NotFound));
    s.create_new(b"first").unwrap();
    assert_eq!(s.read().unwrap(), b"first");
    assert!(temps(dir.path()).is_empty());
}

#[test]
fn create_new_refuses_existing() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(vault_in(&dir), b"old").unwrap();
    let mut s = FsStore::new(vault_in(&dir));
    assert_eq!(s.create_new(b"new"), Err(StoreError::AlreadyExists));
    assert_eq!(fs::read(vault_in(&dir)).unwrap(), b"old");
    assert!(temps(dir.path()).is_empty());
}

#[test]
fn replace_swaps_and_leaves_no_temp() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = FsStore::new(vault_in(&dir));
    s.create_new(b"one").unwrap();
    s.replace(b"two, longer").unwrap();
    assert_eq!(s.read().unwrap(), b"two, longer");
    s.replace(b"3").unwrap();
    assert_eq!(s.read().unwrap(), b"3");
    assert!(temps(dir.path()).is_empty());
}

#[test]
fn replace_creates_a_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = FsStore::new(vault_in(&dir));
    s.replace(b"fresh").unwrap();
    assert_eq!(s.read().unwrap(), b"fresh");
    assert!(temps(dir.path()).is_empty());
}

#[test]
fn read_refuses_oversize_without_reading() {
    let dir = tempfile::tempdir().unwrap();
    // A sparse file: 64 MiB + 1 byte long, but no data blocks, so reading it would
    // be cheap to create and expensive to load.
    let f = fs::File::create(vault_in(&dir)).unwrap();
    f.set_len(u64::try_from(MAX_FILE_LEN).unwrap() + 1).unwrap();
    drop(f);
    let mut s = FsStore::new(vault_in(&dir));
    assert_eq!(s.read(), Err(StoreError::TooLarge));
}

#[test]
fn replace_refuses_oversize() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = FsStore::new(vault_in(&dir));
    s.create_new(b"old").unwrap();
    let big = vec![0u8; MAX_FILE_LEN + 1];
    assert_eq!(s.replace(&big), Err(StoreError::TooLarge));
    assert_eq!(s.create_new(&big), Err(StoreError::TooLarge));
    assert_eq!(s.read().unwrap(), b"old");
    assert!(temps(dir.path()).is_empty());
}

#[test]
fn directory_vault_refused() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(vault_in(&dir)).unwrap();
    let mut s = FsStore::new(vault_in(&dir));
    assert_eq!(s.read(), Err(StoreError::NotARegularFile));
    assert_eq!(s.replace(b"x"), Err(StoreError::NotARegularFile));
    assert_eq!(s.create_new(b"x"), Err(StoreError::AlreadyExists));
    assert!(vault_in(&dir).is_dir());
    assert!(temps(dir.path()).is_empty());
}

#[test]
fn observer_sees_steps_in_order() {
    let dir = tempfile::tempdir().unwrap();
    FsStore::new(vault_in(&dir)).create_new(b"old").unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let mut s = FsStore::with_observer(
        vault_in(&dir),
        Box::new(move |step| log.lock().unwrap().push(step)),
    );
    s.replace(b"new bytes").unwrap();
    let expected: &[SaveStep] = if cfg!(unix) {
        &SaveStep::ALL
    } else {
        &SaveStep::ALL[..5]
    };
    assert_eq!(seen.lock().unwrap().as_slice(), expected);
    assert_eq!(s.read().unwrap(), b"new bytes");
}

#[test]
fn step_names_are_distinct() {
    let names: Vec<&str> = SaveStep::ALL.iter().map(SaveStep::name).collect();
    assert_eq!(
        names,
        [
            "TempCreated",
            "TempHalfWritten",
            "TempWritten",
            "TempSynced",
            "Renamed",
            "DirSynced"
        ]
    );
}

#[test]
fn stale_temp_cleanup_is_exact() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    fs::write(vault_in(&dir), b"vault").unwrap();
    fs::write(d.join("holm.vault.tmp-0123456789abcdef"), b"stale").unwrap();
    let keep = [
        "other.vault.tmp-0123456789abcdef",
        "holm.vault.tmp-XYZ",
        "holm.vault.tmp-0123456789abcde",
        "holm.vault.tmp-0123456789abcdef0",
        "xholm.vault.tmp-0123456789abcdef",
    ];
    for k in keep {
        fs::write(d.join(k), b"keep").unwrap();
    }
    // A directory with a matching name is not a regular file either.
    fs::create_dir(d.join("holm.vault.tmp-bbbbbbbbbbbbbbbb")).unwrap();
    #[cfg(unix)]
    {
        fs::write(d.join("target"), b"target").unwrap();
        std::os::unix::fs::symlink(d.join("target"), d.join("holm.vault.tmp-aaaaaaaaaaaaaaaa"))
            .unwrap();
    }

    let mut s = FsStore::new(vault_in(&dir));
    assert_eq!(s.remove_stale_temps(), Ok(1));
    assert!(!d.join("holm.vault.tmp-0123456789abcdef").exists());
    for k in keep {
        assert_eq!(fs::read(d.join(k)).unwrap(), b"keep", "{k}");
    }
    assert!(d.join("holm.vault.tmp-bbbbbbbbbbbbbbbb").is_dir());
    #[cfg(unix)]
    {
        let link = d.join("holm.vault.tmp-aaaaaaaaaaaaaaaa");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(d.join("target")).unwrap(), b"target");
    }
    assert_eq!(fs::read(vault_in(&dir)).unwrap(), b"vault");
    assert_eq!(s.remove_stale_temps(), Ok(0));

    // Upper-case hex is a near miss. Checked on its own, because on a case-insensitive
    // volume (the macOS default) it would be the same file as the lower-case temp.
    let upper = d.join("holm.vault.tmp-0123456789ABCDEF");
    fs::write(&upper, b"keep").unwrap();
    assert_eq!(s.remove_stale_temps(), Ok(0));
    assert_eq!(fs::read(&upper).unwrap(), b"keep");
}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use holm_core::store::{StoreError, VaultStore};
    use holm_platform::fs_store::FsStore;

    use super::{temps, vault_in};

    /// Sets a directory's mode, and puts 0o700 back on drop so the temp dir can be
    /// removed even if an assertion fails.
    struct DirMode(PathBuf);

    impl DirMode {
        fn set(dir: &Path, mode: u32) -> DirMode {
            fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
            DirMode(dir.to_path_buf())
        }
    }

    impl Drop for DirMode {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn symlinked_vault_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.vault");
        fs::write(&target, b"target").unwrap();
        std::os::unix::fs::symlink(&target, vault_in(&dir)).unwrap();
        let mut s = FsStore::new(vault_in(&dir));
        assert_eq!(s.read(), Err(StoreError::NotARegularFile));
        assert_eq!(s.replace(b"new"), Err(StoreError::NotARegularFile));
        assert_eq!(s.create_new(b"new"), Err(StoreError::AlreadyExists));
        assert_eq!(fs::read(&target).unwrap(), b"target");
        assert!(
            fs::symlink_metadata(vault_in(&dir))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(temps(dir.path()).is_empty());
    }

    #[test]
    fn dangling_symlink_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        std::os::unix::fs::symlink(&target, vault_in(&dir)).unwrap();
        let mut s = FsStore::new(vault_in(&dir));
        assert_eq!(s.read(), Err(StoreError::NotARegularFile));
        assert_eq!(s.create_new(b"new"), Err(StoreError::AlreadyExists));
        assert_eq!(s.replace(b"new"), Err(StoreError::NotARegularFile));
        assert!(!target.exists());
        assert!(temps(dir.path()).is_empty());
    }

    #[test]
    fn fifo_vault_refused_quickly() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = vault_in(&dir);
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut s = FsStore::new(fifo);
            let _ = tx.send((s.read(), s.replace(b"new"), s.create_new(b"new")));
        });
        let (read, replace, create) = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("a FIFO at the vault path blocked");
        assert_eq!(read, Err(StoreError::NotARegularFile));
        assert_eq!(replace, Err(StoreError::NotARegularFile));
        assert_eq!(create, Err(StoreError::AlreadyExists));
        assert!(
            fs::symlink_metadata(vault_in(&dir))
                .unwrap()
                .file_type()
                .is_fifo()
        );
        assert!(temps(dir.path()).is_empty());
    }

    #[test]
    fn files_are_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = FsStore::new(vault_in(&dir));
        s.create_new(b"one").unwrap();
        assert_eq!(mode(&vault_in(&dir)), 0o600);
        s.replace(b"two").unwrap();
        assert_eq!(mode(&vault_in(&dir)), 0o600);
    }

    #[test]
    fn world_writable_dir_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = FsStore::new(vault_in(&dir));
        s.create_new(b"old").unwrap();
        {
            let _guard = DirMode::set(dir.path(), 0o777);
            let denied = Err(StoreError::Io(std::io::ErrorKind::PermissionDenied));
            assert_eq!(s.replace(b"new"), denied);
            fs::remove_file(vault_in(&dir)).unwrap();
            assert_eq!(s.create_new(b"new"), denied);
            assert_eq!(s.read(), Err(StoreError::NotFound));
            assert!(temps(dir.path()).is_empty());
        }
        s.create_new(b"again").unwrap();
        assert_eq!(s.read().unwrap(), b"again");
    }

    #[test]
    fn read_only_dir_keeps_old_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = FsStore::new(vault_in(&dir));
        s.create_new(b"old").unwrap();
        {
            let _guard = DirMode::set(dir.path(), 0o555);
            // Root ignores directory permissions, so the test means nothing there.
            let probe = dir.path().join("probe");
            if fs::write(&probe, b"").is_ok() {
                let _ = fs::remove_file(&probe);
                println!("SKIP read_only_dir_keeps_old_file: running as root");
                return;
            }
            assert_eq!(
                s.replace(b"new"),
                Err(StoreError::Io(std::io::ErrorKind::PermissionDenied))
            );
            assert_eq!(s.read().unwrap(), b"old");
            assert!(temps(dir.path()).is_empty());
        }
        s.replace(b"new").unwrap();
        assert_eq!(s.read().unwrap(), b"new");
        assert!(temps(dir.path()).is_empty());
    }
}
