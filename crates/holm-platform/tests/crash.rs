//! Crash tests: a child process stops itself at each save step, and the vault it
//! leaves behind must open with either the old or the new contents.
//!
//! The child is this same test binary, run again with only `child_save_then_crash`
//! selected. `std::process::exit` ends it on the spot, with no unwinding and no
//! destructors, which models a killed process (not a power cut; see lesson 18).

use std::path::{Path, PathBuf};
use std::process::Command;

use holm_core::clock::SystemClock;
use holm_core::item::{ItemData, ItemInput};
use holm_core::session::Session;
use holm_core::text::{SecretText, Text};
use holm_crypto::MasterPassword;
use holm_crypto::kdf::KdfParams;
use holm_platform::fs_store::{FsStore, SaveStep};

const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";
const CRASH_CODE: i32 = 86;
const DIR_VAR: &str = "HOLM_CRASH_DIR";
const STEP_VAR: &str = "HOLM_CRASH_STEP";

fn pw() -> MasterPassword {
    MasterPassword::new(PW.to_owned())
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

fn vault_path(dir: &Path) -> PathBuf {
    dir.join("holm.vault")
}

fn temps(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp-"))
        .collect()
}

/// The child process. Not a test of its own, so it is ignored in a normal run.
#[test]
#[ignore = "child process for crash_at_every_save_step_leaves_old_or_new"]
fn child_save_then_crash() {
    let dir = std::env::var_os(DIR_VAR).expect("HOLM_CRASH_DIR must be set");
    let step = std::env::var(STEP_VAR).expect("HOLM_CRASH_STEP must be set");
    let observer = Box::new(move |s: SaveStep| {
        if s.name() == step {
            std::process::exit(CRASH_CODE);
        }
    });
    let store = FsStore::with_observer(vault_path(Path::new(&dir)), observer);
    let mut session = Session::new(store, Box::new(SystemClock::new()));
    session.unlock(&pw()).unwrap();
    session.add_item(login("new")).unwrap();
    panic!("the save finished without reaching the crash step");
}

#[test]
fn crash_at_every_save_step_leaves_old_or_new() {
    let exe = std::env::current_exe().unwrap();
    for step in SaveStep::ALL {
        if step == SaveStep::DirSynced && !cfg!(unix) {
            continue;
        }
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = Session::new(
                FsStore::new(vault_path(dir.path())),
                Box::new(SystemClock::new()),
            );
            s.create(&pw(), &KdfParams::FLOOR).unwrap();
            s.add_item(login("old")).unwrap();
            s.lock();
        }

        let out = Command::new(&exe)
            .args([
                "child_save_then_crash",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(DIR_VAR, dir.path())
            .env(STEP_VAR, step.name())
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(CRASH_CODE),
            "step {}: child did not stop there\nstdout: {}\nstderr: {}",
            step.name(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        // Before the temp steps are done the crash must have left a temp behind; this
        // proves the crash really stopped there and that unlock is what removes it.
        if matches!(
            step,
            SaveStep::TempCreated
                | SaveStep::TempHalfWritten
                | SaveStep::TempWritten
                | SaveStep::TempSynced
        ) {
            assert!(
                !temps(dir.path()).is_empty(),
                "step {}: no temp left before unlock",
                step.name()
            );
        }

        let mut s = Session::new(
            FsStore::new(vault_path(dir.path())),
            Box::new(SystemClock::new()),
        );
        s.unlock(&pw()).unwrap();
        let mut titles: Vec<String> = s
            .active_items()
            .unwrap()
            .map(|i| i.title().to_owned())
            .collect();
        titles.sort();
        let expected: &[&str] = match step {
            SaveStep::TempCreated
            | SaveStep::TempHalfWritten
            | SaveStep::TempWritten
            | SaveStep::TempSynced => &["old"],
            SaveStep::Renamed | SaveStep::DirSynced => &["new", "old"],
        };
        assert_eq!(titles, expected, "step {}", step.name());
        assert!(
            temps(dir.path()).is_empty(),
            "step {}: temp left: {:?}",
            step.name(),
            temps(dir.path())
        );
    }
}
