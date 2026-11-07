#![forbid(unsafe_code)]
//! After an upgrade from format v1, `holm` says once on stderr that the backup copy
//! is still kept. It never deletes it.

mod common;

use std::fs;
use std::process::ExitCode;

use common::{FakeTerminal, run, vault_dir};
use holm_core::clock::SystemClock;
use holm_core::session::Session;
use holm_crypto::MasterPassword;
use holm_platform::fs_store::FsStore;

const GOLDEN_V1: &[u8] = include_bytes!("../../holm-core/tests/vectors/golden-v1.vault");
const GOLDEN_PW: &str = "caf\u{e9} golden";

fn bak_files(dir: &std::path::Path) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("v1-")
        })
        .count()
}

#[test]
fn cli_prints_backup_line() {
    let (dir, path) = vault_dir();
    fs::write(&path, GOLDEN_V1).unwrap();
    // Unlock and save once: this migrates the file and keeps the v1 copy.
    let mut s = Session::new(FsStore::new(&path), Box::new(SystemClock::new()));
    s.unlock(&MasterPassword::new(GOLDEN_PW.to_owned()))
        .unwrap();
    s.save().unwrap();
    drop(s);
    let kept = bak_files(dir.path());
    assert_eq!(kept, 1, "the migration keeps one backup copy");

    let mut term = FakeTerminal::new(&[GOLDEN_PW]);
    let ran = run(&path, &["list"], &mut term);
    assert_eq!(ran.code, ExitCode::SUCCESS, "err: {}", ran.err);
    assert!(
        ran.err.contains("deleting does not remove Time Machine")
            || ran.err.contains("Deleting does not remove Time Machine"),
        "stderr: {}",
        ran.err
    );
    assert!(!ran.out.contains("Time Machine"), "stdout stays clean");
    assert_eq!(
        bak_files(dir.path()),
        kept,
        "the CLI never deletes the copy"
    );
}

#[test]
fn cli_prints_no_backup_line_without_migration() {
    let (_dir, path) = vault_dir();
    common::init(&path);
    let mut term = FakeTerminal::new(&[common::PW]);
    let ran = run(&path, &["list"], &mut term);
    assert!(!ran.err.contains("Time Machine"), "stderr: {}", ran.err);
}
