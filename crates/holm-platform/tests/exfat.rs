//! `FsStore` on a real exFAT volume (a USB stick's usual format), from a small disk
//! image made with `hdiutil`. exFAT has no hard links, so `create_new` takes its
//! fallback path here. macOS only; the image is detached and deleted even when the
//! test fails.

#[cfg(target_os = "macos")]
mod macos {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    use holm_core::clock::SystemClock;
    use holm_core::item::{ItemData, ItemInput};
    use holm_core::session::Session;
    use holm_core::store::VaultStore;
    use holm_core::text::{SecretText, Text};
    use holm_crypto::MasterPassword;
    use holm_crypto::kdf::KdfParams;
    use holm_platform::fs_store::FsStore;

    /// Runs `hdiutil`. `None` means `hdiutil` is not installed; any other failure
    /// to start it, or a non-zero exit, panics.
    fn hdiutil(args: &[&std::ffi::OsStr]) -> Option<Output> {
        match Command::new("hdiutil").args(args).output() {
            Ok(out) => {
                assert!(
                    out.status.success(),
                    "hdiutil {args:?} failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                Some(out)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => panic!("could not run hdiutil: {e}"),
        }
    }

    /// Detaches the volume on drop, so a failed assertion never leaves it mounted.
    /// The image file itself lives in a `TempDir` declared before this guard, so it
    /// is deleted right after the detach.
    struct Mounted(PathBuf);

    impl Drop for Mounted {
        fn drop(&mut self) {
            let ok = Command::new("hdiutil")
                .arg("detach")
                .arg(&self.0)
                .output()
                .is_ok_and(|o| o.status.success());
            if !ok {
                let _ = Command::new("hdiutil")
                    .arg("detach")
                    .arg("-force")
                    .arg(&self.0)
                    .output();
            }
        }
    }

    fn temps(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect()
    }

    fn login(title: &str) -> ItemInput {
        ItemInput {
            title: Text::new(title.to_owned()),
            category: None,
            favourite: false,
            data: ItemData::Login {
                username: Text::new("user".to_owned()),
                password: SecretText::new("pw-EXAMPLE".to_owned()),
                urls: Vec::new(),
                notes: SecretText::new(String::new()),
            },
        }
    }

    pub(super) fn run() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("holm-exfat.dmg");
        let mnt = tmp.path().join("mnt");
        std::fs::create_dir(&mnt).unwrap();
        let created = hdiutil(&[
            "create".as_ref(),
            "-size".as_ref(),
            "32m".as_ref(),
            "-fs".as_ref(),
            "ExFAT".as_ref(),
            "-volname".as_ref(),
            "HOLMEXFAT".as_ref(),
            image.as_os_str(),
        ]);
        if created.is_none() {
            println!("SKIP exfat: hdiutil not found");
            return;
        }
        // Set the guard before attaching: if attach half-succeeds, detach still runs.
        let _mounted = Mounted(mnt.clone());
        hdiutil(&[
            "attach".as_ref(),
            "-nobrowse".as_ref(),
            "-mountpoint".as_ref(),
            mnt.as_os_str(),
            image.as_os_str(),
        ])
        .expect("hdiutil disappeared between create and attach");

        let path = mnt.join("holm.vault");
        let mut s = FsStore::new(&path);
        s.create_new(b"one").unwrap();
        s.replace(b"two").unwrap();
        s.replace(b"three, the last").unwrap();
        assert_eq!(s.read().unwrap(), b"three, the last");
        assert!(temps(&mnt).is_empty(), "{:?}", temps(&mnt));
        std::fs::remove_file(&path).unwrap();

        let pw = MasterPassword::new("correct-Horse-battery-staple-EXAMPLE-9".to_owned());
        let mut session = Session::new(FsStore::new(&path), Box::new(SystemClock::new()));
        session.create(&pw, &KdfParams::FLOOR).unwrap();
        session.add_item(login("on exFAT")).unwrap();
        session.lock();
        session.unlock(&pw).unwrap();
        let titles: Vec<&str> = session.active_items().unwrap().map(|i| i.title()).collect();
        assert_eq!(titles, ["on exFAT"]);
        assert!(temps(&mnt).is_empty(), "{:?}", temps(&mnt));
    }
}

#[test]
fn exfat_volume_saves_and_reopens() {
    #[cfg(target_os = "macos")]
    macos::run();
    #[cfg(not(target_os = "macos"))]
    println!("SKIP exfat: macOS only (needs hdiutil)");
}
