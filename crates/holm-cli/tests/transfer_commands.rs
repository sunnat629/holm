//! `holm import` and `holm export` against a vault in a temporary folder, with a fake
//! terminal.

mod common;

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;

use common::{FakeTerminal, Kind, PW, Ran, init, run, session, vault_dir};
use holm_cli::CliError;
use holm_cli::commands::transfer::import_error;
use holm_core::clock::SystemClock;
use holm_core::envelope::VaultError;
use holm_core::error::CoreError;
use holm_core::export::EXPORT_WARNING;
use holm_core::import::{IMPORT_DELETE_SOURCE_WARNING, MAX_IMPORT_BYTES};
use holm_core::session::Session;
use holm_core::store::StoreError;
use holm_crypto::MasterPassword;
use holm_platform::fs_store::FsStore;

fn ok(ran: &Ran) {
    assert_eq!(
        ran.code,
        ExitCode::SUCCESS,
        "out: {}\nerr: {}",
        ran.out,
        ran.err
    );
}

fn failed(ran: &Ran) {
    assert_eq!(
        ran.code,
        ExitCode::FAILURE,
        "out: {}\nerr: {}",
        ran.out,
        ran.err
    );
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../holm-core/tests/fixtures/import/holm.csv")
}

fn count(path: &Path) -> usize {
    session(path).active_items().unwrap().count()
}

#[test]
fn import_preview_confirm_report_and_warning() {
    let (_dir, path) = vault_dir();
    init(&path);
    let file = fixture();
    let file = file.to_str().unwrap();

    // Declined: nothing changes.
    let mut term = FakeTerminal::new(&[PW, "no"]);
    let ran = run(&path, &["import", file], &mut term);
    failed(&ran);
    assert_eq!(
        term.prompts,
        vec![
            (Kind::Secret, "Master password: ".to_owned()),
            (Kind::Line, "Type import to add 4 items: ".to_owned()),
        ]
    );
    assert!(ran.out.contains("1 login"), "{}", ran.out);
    assert!(ran.out.contains("1 crypto address"), "{}", ran.out);
    assert!(ran.out.contains("1 recovery phrase"), "{}", ran.out);
    assert!(ran.out.contains("1 secure note"), "{}", ran.out);
    // The fixture's categories (Work, Personal) are built into every new vault.
    assert!(!ran.out.contains("a category this vault"), "{}", ran.out);
    assert!(ran.err.contains(&CliError::NotConfirmed.to_string()));
    assert!(!ran.err.contains(IMPORT_DELETE_SOURCE_WARNING));
    assert_eq!(count(&path), 0);

    let mut term = FakeTerminal::new(&[PW, "import"]);
    let ran = run(&path, &["import", file], &mut term);
    ok(&ran);
    assert!(ran.out.contains("Imported 4 items."), "{}", ran.out);
    assert!(ran.err.contains(IMPORT_DELETE_SOURCE_WARNING));
    assert!(!ran.out.contains("EXAMPLE") && !ran.err.contains("EXAMPLE"));
    assert_eq!(count(&path), 4);

    // Again: every row is a duplicate, so there is nothing to confirm.
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["import", file], &mut term);
    ok(&ran);
    assert!(ran.out.contains("4 duplicates"), "{}", ran.out);
    assert!(ran.out.contains("Nothing to import."), "{}", ran.out);
    assert_eq!(term.kinds(), vec![Kind::Secret]);
    assert_eq!(count(&path), 4);
}

#[test]
fn import_oversize_refused_before_prompt() {
    let (dir, path) = vault_dir();
    init(&path);
    let big = dir.path().join("big.csv");
    fs::File::create(&big)
        .unwrap()
        .set_len(u64::try_from(MAX_IMPORT_BYTES).unwrap() + 1)
        .unwrap();
    let missing = dir.path().join("missing.csv");
    let folder = dir.path().join("folder.csv");
    fs::create_dir(&folder).unwrap();
    for (file, want) in [
        (&big, CliError::ImportTooLarge),
        (&missing, CliError::ImportFileMissing),
        (&folder, CliError::ImportNotAFile),
    ] {
        let mut term = FakeTerminal::new(&[PW, "import"]);
        let ran = run(&path, &["import", file.to_str().unwrap()], &mut term);
        failed(&ran);
        assert!(ran.err.contains(&want.to_string()), "{}", ran.err);
        assert!(!ran.err.contains("vault file") && !ran.err.contains("64 MiB"));
        assert!(term.prompts.is_empty());
    }

    // A file Holm can't parse is refused before the vault is opened, too.
    let bad = dir.path().join("bad.json");
    fs::write(&bad, "not json").unwrap();
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["import", bad.to_str().unwrap()], &mut term);
    failed(&ran);
    assert!(term.prompts.is_empty());
    assert!(!ran.err.contains("not json"));
}

#[test]
fn import_reports_rows_by_number_only() {
    let (dir, path) = vault_dir();
    init(&path);
    let file = dir.path().join("rows.csv");
    fs::write(
        &file,
        "title,username,password,type,address,category\n\
         Good,u,EXAMPLE-good-pw,login,,Nowhere\n\
         Bad,u,CANARY-row-secret-1,spaceship,,\n\
         Wallet,,,crypto,,\n",
    )
    .unwrap();
    let mut term = FakeTerminal::new(&[PW, "import"]);
    let ran = run(&path, &["import", file.to_str().unwrap()], &mut term);
    ok(&ran);
    assert!(ran.out.contains("2 rows can't be imported"), "{}", ran.out);
    assert!(ran.out.contains("row 2: "), "{}", ran.out);
    assert!(ran.out.contains("row 3: "), "{}", ran.out);
    assert!(ran.out.contains("1 row names a category"), "{}", ran.out);
    assert!(ran.out.contains("Imported 1 item."), "{}", ran.out);
    for text in ["CANARY", "spaceship", "EXAMPLE", "Bad", "Wallet", "Nowhere"] {
        assert!(!ran.out.contains(text) && !ran.err.contains(text), "{text}");
    }
    assert_eq!(count(&path), 1);
}

#[test]
fn export_shows_warning_then_confirms_then_asks_password() {
    let (dir, path) = vault_dir();
    init(&path);
    let file = dir.path().join("export.csv");
    let file_str = file.to_str().unwrap();

    let transcript = Rc::new(RefCell::new(String::new()));
    let mut term = FakeTerminal::new(&[PW, "export", PW]);
    term.transcript = Some(Rc::clone(&transcript));
    let ran = run(&path, &["export", file_str], &mut term);
    ok(&ran);
    let t = transcript.borrow();
    let warning = t.find(EXPORT_WARNING).unwrap();
    let confirm = t.find("[Type export to continue: ]").unwrap();
    let again = t.find("[Master password again: ]").unwrap();
    assert!(warning < confirm && confirm < again, "{t}");
    assert!(t.find("[Master password: ]").unwrap() < warning);
    assert!(ran.out.contains("Exported 0 items"), "{}", ran.out);
    assert!(file.is_file());

    // Declined: no file, and no second password prompt.
    let file2 = dir.path().join("export2.csv");
    let mut term = FakeTerminal::new(&[PW, "no", PW]);
    let ran = run(&path, &["export", file2.to_str().unwrap()], &mut term);
    failed(&ran);
    assert!(ran.err.contains(&CliError::NotConfirmed.to_string()));
    assert_eq!(term.unused(), 1);
    assert!(!file2.exists());

    // A wrong second password: no file.
    let mut term = FakeTerminal::new(&[PW, "export", "wrong-EXAMPLE"]);
    let ran = run(&path, &["export", file2.to_str().unwrap()], &mut term);
    failed(&ran);
    assert!(ran.err.contains(&CliError::WrongPassword.to_string()));
    assert!(!file2.exists());
}

#[test]
fn export_refuses_existing_file_before_prompt() {
    let (dir, path) = vault_dir();
    init(&path);
    let file = dir.path().join("there.csv");
    fs::write(&file, "keep me").unwrap();
    for args in [
        &["export", file.to_str().unwrap()][..],
        &["export", "--backup", file.to_str().unwrap()],
    ] {
        let mut term = FakeTerminal::new(&[PW, "export", PW]);
        let ran = run(&path, args, &mut term);
        failed(&ran);
        assert!(
            ran.err.contains(&CliError::FileExists.to_string()),
            "{}",
            ran.err
        );
        assert!(term.prompts.is_empty());
        assert_eq!(fs::read_to_string(&file).unwrap(), "keep me");
    }
}

#[cfg(unix)]
#[test]
fn export_file_is_0600_and_reimports() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, path) = vault_dir();
    init(&path);
    let mut term = FakeTerminal::new(&[PW, "import"]);
    ok(&run(
        &path,
        &["import", fixture().to_str().unwrap()],
        &mut term,
    ));

    let file = dir.path().join("export.csv");
    let mut term = FakeTerminal::new(&[PW, "export", PW]);
    let ran = run(&path, &["export", file.to_str().unwrap()], &mut term);
    ok(&ran);
    assert!(ran.out.contains("Exported 4 items"), "{}", ran.out);
    let mode = fs::metadata(&file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    let (_dir2, path2) = vault_dir();
    init(&path2);
    let mut term = FakeTerminal::new(&[PW, "import"]);
    let ran = run(&path2, &["import", file.to_str().unwrap()], &mut term);
    ok(&ran);
    assert_eq!(count(&path2), 4);
}

#[test]
fn export_backup_opens_with_same_password() {
    let (dir, path) = vault_dir();
    init(&path);
    let mut term = FakeTerminal::new(&[PW, "import"]);
    ok(&run(
        &path,
        &["import", fixture().to_str().unwrap()],
        &mut term,
    ));

    let backup = dir.path().join("backup.holm");
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(
        &path,
        &["export", "--backup", backup.to_str().unwrap()],
        &mut term,
    );
    ok(&ran);
    assert_eq!(term.kinds(), vec![Kind::Secret]);
    let mut s = Session::new(FsStore::new(&backup), Box::new(SystemClock::new()));
    s.unlock(&MasterPassword::new(PW.to_owned())).unwrap();
    assert_eq!(s.active_items().unwrap().count(), 4);
}

#[test]
fn import_core_error_before_rows_is_failed_not_unsaved() {
    // Nothing went in, so nothing can be "added but not saved".
    for e in [CoreError::Locked, CoreError::UnknownCategory] {
        assert!(matches!(import_error(&e), CliError::Failed), "{e:?}");
    }
    // Only a failed save leaves the items in memory.
    let io = StoreError::Io(std::io::ErrorKind::Other);
    assert!(matches!(
        import_error(&CoreError::Store(io)),
        CliError::ImportNotSaved
    ));
    assert!(matches!(
        import_error(&CoreError::Vault(VaultError::Crypto)),
        CliError::ImportNotSaved
    ));
    assert!(matches!(
        import_error(&CoreError::TooManyItems),
        CliError::ImportTooManyItems
    ));
    assert!(matches!(
        import_error(&CoreError::Vault(VaultError::TooLargeToSave)),
        CliError::ImportTooLargeToSave
    ));
}

#[cfg(unix)]
#[test]
fn import_unreadable_file_says_no_access() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, path) = vault_dir();
    init(&path);
    let locked = dir.path().join("locked.csv");
    fs::write(&locked, "x").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let mut term = FakeTerminal::new(&[PW, "import"]);
    let ran = run(&path, &["import", locked.to_str().unwrap()], &mut term);
    let readable = fs::File::open(&locked).is_ok();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).unwrap();
    if readable {
        return; // running as root: the file is readable, nothing to assert
    }
    failed(&ran);
    assert!(
        ran.err.contains("Holm isn't allowed to read that file."),
        "{}",
        ran.err
    );
    assert!(term.prompts.is_empty());
}
