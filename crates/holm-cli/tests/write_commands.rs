//! `holm add`, `edit`, `rm`, `passwd` and `--copy` against a vault in a temporary
//! folder, with a fake terminal and a fake clipboard.

mod common;

use std::cell::{Cell, RefCell};
use std::path::Path;
use std::process::ExitCode;
use std::rc::Rc;

use common::{
    ClipState, FakeTerminal, Kind, PW, Ran, env, env_with_clip, init, run, run_env, session, usage,
    vault_dir,
};
use holm_cli::CliError;
use holm_cli::args::CopyField;
use holm_cli::commands::copy::value_of;
use holm_cli::output::write_error;
use holm_core::error::CoreError;
use holm_core::generator::PasswordSpec;
use holm_core::item::{ItemData, ItemId, ItemInput};
use holm_core::session::Session;
use holm_core::text::{SecretText, Text};
use holm_crypto::MasterPassword;
use holm_platform::fs_store::FsStore;

const NEW_PW: &str = "Another-strong-EXAMPLE-master-phrase-42";

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

/// The 8-hex prefix `add` printed.
fn added(ran: &Ran) -> String {
    ok(ran);
    let line = ran.out.lines().last().unwrap();
    let prefix = line
        .strip_prefix("Added ")
        .and_then(|l| l.strip_suffix('.'))
        .unwrap_or_else(|| panic!("unexpected add output: {line}"));
    assert_eq!(prefix.len(), 8);
    prefix.to_owned()
}

/// The full id of the one item whose id starts with `prefix`.
fn id_of(s: &Session<FsStore>, prefix: &str) -> ItemId {
    let mut ids: Vec<ItemId> = s
        .active_items()
        .unwrap()
        .map(holm_core::item::Item::id)
        .collect();
    ids.extend(
        s.search(&holm_core::search::Query {
            view: holm_core::search::View::Trash,
            ..holm_core::search::Query::default()
        })
        .unwrap()
        .iter()
        .map(|h| h.id),
    );
    let found: Vec<ItemId> = ids
        .into_iter()
        .filter(|id| id.to_hex().starts_with(prefix))
        .collect();
    assert_eq!(found.len(), 1);
    found[0]
}

fn count(path: &Path) -> usize {
    session(path).active_items().unwrap().count()
}

fn export(path: &Path) -> String {
    let mut s = session(path);
    let csv = s.export_csv(&MasterPassword::new(PW.to_owned())).unwrap();
    String::from_utf8(csv.expose().to_vec()).unwrap()
}

fn add_login(path: &Path, password: &str) -> String {
    let mut term = FakeTerminal::new(&[PW, password, password]);
    added(&run(
        path,
        &["add", "login", "--title", "Mail", "--username", "me"],
        &mut term,
    ))
}

fn add_phrase(path: &Path, phrase: &str) -> String {
    let mut term = FakeTerminal::new(&[PW, phrase, phrase]);
    added(&run(path, &["add", "phrase", "--title", "Seed"], &mut term))
}

#[test]
fn add_each_type_then_get() {
    let (_dir, path) = vault_dir();
    init(&path);

    let mut term = FakeTerminal::new(&[PW, "EXAMPLE-pw-1", "EXAMPLE-pw-1", "EXAMPLE notes"]);
    let login = added(&run(
        &path,
        &[
            "add",
            "login",
            "--title",
            "Mail",
            "--username",
            "me@example.com",
            "--url",
            "https://mail.example.com",
            "--url",
            "https://example.org",
            "--favourite",
            "--with-notes",
        ],
        &mut term,
    ));
    assert_eq!(
        term.prompts,
        vec![
            (Kind::Secret, "Master password: ".to_owned()),
            (Kind::Secret, "Password: ".to_owned()),
            (Kind::Secret, "Repeat the password: ".to_owned()),
            (Kind::Secret, "Notes: ".to_owned()),
        ]
    );

    let mut term = FakeTerminal::new(&[PW, "EXAMPLE-0xaddr", "EXAMPLE-memo"]);
    let crypto = added(&run(
        &path,
        &["add", "crypto", "--title", "Wallet", "--chain", "Bitcoin"],
        &mut term,
    ));
    assert_eq!(term.kinds(), vec![Kind::Secret; 3]);

    let phrase = add_phrase(&path, "example word00 word01 word02");

    let mut term = FakeTerminal::new(&[PW, "EXAMPLE secret note"]);
    let note = added(&run(&path, &["add", "note", "--title", "Note"], &mut term));
    assert_eq!(term.kinds(), vec![Kind::Secret; 2]);

    for (prefix, title, kind, hidden) in [
        (&login, "Mail", "login", "password: (hidden)"),
        (&crypto, "Wallet", "crypto", "address: (hidden)"),
        (&phrase, "Seed", "phrase", "phrase: (hidden)"),
        (&note, "Note", "note", "body: (hidden)"),
    ] {
        let mut term = FakeTerminal::new(&[PW]);
        let ran = run(&path, &["get", prefix], &mut term);
        ok(&ran);
        assert!(
            ran.out.contains(&format!("title: {title}\n")),
            "{}",
            ran.out
        );
        assert!(ran.out.contains(&format!("type: {kind}\n")));
        assert!(ran.out.contains(hidden));
        assert!(!ran.out.contains("EXAMPLE"), "{}", ran.out);
    }

    let s = session(&path);
    let item = s.item(id_of(&s, &login)).unwrap();
    assert!(item.favourite());
    let ItemData::Login {
        username,
        password,
        urls,
        notes,
    } = item.data()
    else {
        panic!("not a login");
    };
    assert_eq!(username.as_str(), "me@example.com");
    assert_eq!(password.expose(), "EXAMPLE-pw-1");
    assert_eq!(urls.len(), 2);
    assert_eq!(notes.expose(), "EXAMPLE notes");
    let ItemData::CryptoAddress {
        chain,
        address,
        memo,
        ..
    } = s.item(id_of(&s, &crypto)).unwrap().data()
    else {
        panic!("not crypto");
    };
    assert_eq!(
        (chain.as_str(), address.expose(), memo.expose()),
        ("Bitcoin", "EXAMPLE-0xaddr", "EXAMPLE-memo")
    );
    let ItemData::SecureNote { body } = s.item(id_of(&s, &note)).unwrap().data() else {
        panic!("not a note");
    };
    assert_eq!(body.expose(), "EXAMPLE secret note");
}

#[test]
fn add_flags_are_checked_before_any_prompt() {
    let (_dir, path) = vault_dir();
    init(&path);
    for line in [
        &["add", "login"][..],
        &["add", "note", "--title", "N", "--username", "u"],
        &["add", "crypto", "--title", "W", "--generate"],
        &[
            "add",
            "phrase",
            "--title",
            "P",
            "--url",
            "https://x.example",
        ],
        &["add", "note", "--title", "N", "--with-notes"],
        &["add", "car", "--title", "C"],
        &["add", "login", "--title", "A", "--title", "B"],
    ] {
        let mut term = FakeTerminal::new(&[]);
        let ran = run(&path, line, &mut term);
        assert_eq!(ran.code, usage(), "{line:?}: {}", ran.err);
        assert!(term.prompts.is_empty(), "{line:?}");
    }
}

#[test]
fn add_login_generate_uses_vault_spec() {
    let (_dir, path) = vault_dir();
    init(&path);
    {
        let mut s = session(&path);
        let mut settings = s.settings().unwrap().clone();
        settings.password = PasswordSpec {
            length: 64,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            avoid_lookalikes: false,
            min_digits: 1,
            min_symbols: 0,
        };
        s.update_settings(settings, Some(&MasterPassword::new(PW.to_owned())))
            .unwrap();
    }
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(
        &path,
        &["add", "login", "--title", "Gen", "--generate"],
        &mut term,
    );
    let prefix = added(&ran);
    assert_eq!(term.kinds(), vec![Kind::Secret]);
    let s = session(&path);
    let ItemData::Login { password, .. } = s.item(id_of(&s, &prefix)).unwrap().data() else {
        panic!("not a login");
    };
    assert_eq!(password.len(), 64);
    assert!(password.expose().bytes().all(|b| b.is_ascii_digit()));
    // The generated password is never printed.
    assert!(!ran.out.contains(password.expose()) && !ran.err.contains(password.expose()));
}

#[test]
fn add_password_mismatch_adds_nothing() {
    let (_dir, path) = vault_dir();
    init(&path);
    let mut term = FakeTerminal::new(&[PW, "EXAMPLE-one-1", "EXAMPLE-two-2"]);
    let ran = run(&path, &["add", "login", "--title", "Mail"], &mut term);
    failed(&ran);
    assert!(ran.err.contains("don't match"), "{}", ran.err);
    assert_eq!(count(&path), 0);

    let mut term = FakeTerminal::new(&[PW, "word00 word01", "word00 word02"]);
    failed(&run(
        &path,
        &["add", "phrase", "--title", "Seed"],
        &mut term,
    ));
    assert_eq!(count(&path), 0);
}

#[test]
fn edit_keeps_unchanged_secrets() {
    let (_dir, path) = vault_dir();
    init(&path);
    let login = add_login(&path, "EXAMPLE-keep-pw");
    let phrase = add_phrase(&path, "example keep00 keep01 keep02");
    let mut term = FakeTerminal::new(&[
        PW,
        "EXAMPLE-0xkeep",
        "EXAMPLE-keep-memo",
        "EXAMPLE keep notes",
    ]);
    let crypto = added(&run(
        &path,
        &["add", "crypto", "--title", "Wallet", "--with-notes"],
        &mut term,
    ));
    let before = export(&path);

    for (prefix, title) in [
        (&login, "Mail 2"),
        (&phrase, "Seed 2"),
        (&crypto, "Wallet 2"),
    ] {
        let mut term = FakeTerminal::new(&[PW]);
        let ran = run(
            &path,
            &["edit", prefix, "--title", title, "--favourite"],
            &mut term,
        );
        ok(&ran);
        assert_eq!(term.kinds(), vec![Kind::Secret]);
    }
    let after = export(&path);
    for secret in [
        "EXAMPLE-keep-pw",
        "example keep00 keep01 keep02",
        "EXAMPLE-0xkeep",
        "EXAMPLE-keep-memo",
        "EXAMPLE keep notes",
    ] {
        assert!(before.contains(secret), "{secret}");
        assert!(after.contains(secret), "{secret} lost by edit");
    }
    assert!(after.contains("Mail 2") && after.contains("Seed 2") && after.contains("Wallet 2"));

    // A new password, typed twice; the username and URLs stay.
    let mut term = FakeTerminal::new(&[PW, "EXAMPLE-new-pw", "EXAMPLE-new-pw"]);
    ok(&run(
        &path,
        &[
            "edit",
            &login,
            "--new-password",
            "--url",
            "https://new.example",
        ],
        &mut term,
    ));
    let s = session(&path);
    let ItemData::Login {
        username,
        password,
        urls,
        ..
    } = s.item(id_of(&s, &login)).unwrap().data()
    else {
        panic!("not a login");
    };
    assert_eq!(username.as_str(), "me");
    assert_eq!(password.expose(), "EXAMPLE-new-pw");
    assert_eq!(urls.len(), 1);

    // Nothing to change is a usage error, before any prompt.
    let mut term = FakeTerminal::new(&[]);
    assert_eq!(run(&path, &["edit", &login], &mut term).code, usage());
}

#[test]
fn edit_type_change_impossible() {
    let (_dir, path) = vault_dir();
    init(&path);
    let mut term = FakeTerminal::new(&[PW, "EXAMPLE note body"]);
    let note = added(&run(&path, &["add", "note", "--title", "Note"], &mut term));

    for flags in [
        &["--username", "x"][..],
        &["--url", "https://x.example"],
        &["--new-password"],
        &["--generate"],
    ] {
        let mut args = vec!["edit", note.as_str()];
        args.extend_from_slice(flags);
        let mut term = FakeTerminal::new(&[PW, "unused", "unused"]);
        let ran = run(&path, &args, &mut term);
        failed(&ran);
        assert!(
            ran.err.contains(&CliError::TypeChange.to_string()),
            "{}",
            ran.err
        );
        // Refused before any prompt for a new secret.
        assert_eq!(term.kinds(), vec![Kind::Secret]);
    }
    let s = session(&path);
    let item = s.item(id_of(&s, &note)).unwrap();
    assert_eq!(item.title(), "Note");

    // The core refuses a type change, and the CLI maps it to the same message.
    let mut s = session(&path);
    let id = id_of(&s, &note);
    let as_login = ItemInput {
        title: Text::new("Note".to_owned()),
        category: None,
        favourite: false,
        data: ItemData::Login {
            username: Text::new("x".to_owned()),
            password: SecretText::new(String::new()),
            urls: Vec::new(),
            notes: SecretText::new(String::new()),
        },
    };
    let e = s.update_item(id, as_login).unwrap_err();
    assert_eq!(e, CoreError::TypeChange);
    assert!(matches!(write_error(&e), CliError::TypeChange));
}

#[test]
fn rm_trashes_and_forever_needs_typed_confirm() {
    let (_dir, path) = vault_dir();
    init(&path);
    let login = add_login(&path, "EXAMPLE-rm-pw");

    // Not in the Trash yet: --forever refuses before the confirm.
    let mut term = FakeTerminal::new(&[PW, "delete"]);
    let ran = run(&path, &["rm", "--forever", &login], &mut term);
    failed(&ran);
    assert!(ran.err.contains("isn't in the Trash"), "{}", ran.err);
    assert_eq!(term.kinds(), vec![Kind::Secret]);

    let mut term = FakeTerminal::new(&[PW]);
    ok(&run(&path, &["rm", &login], &mut term));
    assert_eq!(count(&path), 0);
    let s = session(&path);
    assert!(s.item(id_of(&s, &login)).unwrap().trashed().is_some());

    // Anything but "delete" keeps it.
    let mut term = FakeTerminal::new(&[PW, "yes"]);
    let ran = run(&path, &["rm", "--forever", &login], &mut term);
    failed(&ran);
    assert_eq!(
        term.prompts[1],
        (
            Kind::Line,
            "Type delete to remove this item for good: ".to_owned()
        )
    );
    let s = session(&path);
    assert!(s.item(id_of(&s, &login)).is_ok());

    let mut term = FakeTerminal::new(&[PW, "delete"]);
    ok(&run(&path, &["rm", "--forever", &login], &mut term));
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["get", &login], &mut term);
    failed(&ran);
    assert!(ran.err.contains(&CliError::NotFound.to_string()));
}

#[test]
fn passwd_changes_and_old_fails() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "EXAMPLE-passwd-pw");
    let mut term = FakeTerminal::new(&[PW, PW, NEW_PW, NEW_PW]);
    let ran = run(&path, &["passwd"], &mut term);
    ok(&ran);
    assert_eq!(
        term.prompts,
        vec![
            (Kind::Secret, "Master password: ".to_owned()),
            (Kind::Secret, "Current master password: ".to_owned()),
            (Kind::Secret, "New master password: ".to_owned()),
            (Kind::Secret, "Repeat the new master password: ".to_owned()),
        ]
    );
    let mut old = Session::new(
        FsStore::new(&path),
        Box::new(holm_core::clock::SystemClock::new()),
    );
    assert!(old.unlock(&MasterPassword::new(PW.to_owned())).is_err());
    let mut new = Session::new(
        FsStore::new(&path),
        Box::new(holm_core::clock::SystemClock::new()),
    );
    new.unlock(&MasterPassword::new(NEW_PW.to_owned())).unwrap();
    assert_eq!(new.active_items().unwrap().count(), 1);

    // A wrong current password changes nothing. The core checks it (through the
    // throttle) together with the change, after the new password is typed.
    let mut term = FakeTerminal::new(&[NEW_PW, "wrong-EXAMPLE", PW, PW]);
    let ran = run(&path, &["passwd"], &mut term);
    failed(&ran);
    assert!(ran.err.contains(&CliError::WrongPassword.to_string()));
    let mut still = Session::new(
        FsStore::new(&path),
        Box::new(holm_core::clock::SystemClock::new()),
    );
    still
        .unlock(&MasterPassword::new(NEW_PW.to_owned()))
        .unwrap();
}

#[test]
fn passwd_weak_refused() {
    let (_dir, path) = vault_dir();
    init(&path);
    let mut term = FakeTerminal::new(&[PW, PW, "password1", "password1"]);
    let ran = run(&path, &["passwd"], &mut term);
    failed(&ran);
    assert!(ran.err.contains(&CliError::WeakPassword.to_string()));
    // Refused before the repeat.
    assert_eq!(term.unused(), 1);
    // The old password still opens the vault.
    let _ = session(&path);

    let mut term = FakeTerminal::new(&[PW, PW, NEW_PW, "different-EXAMPLE"]);
    failed(&run(&path, &["passwd"], &mut term));
    let _ = session(&path);
}

#[test]
fn copy_waits_then_clears_only_if_unchanged() {
    let (dir, path) = vault_dir();
    init(&path);
    let login = add_login(&path, "EXAMPLE-copy-pw");

    let clip = Rc::new(RefCell::new(ClipState::default()));
    let env = env_with_clip(&clip);
    let lock_free = Rc::new(Cell::new(false));
    let mut term = FakeTerminal::new(&[PW]);
    let (seen, folder) = (Rc::clone(&lock_free), dir.path().to_owned());
    let state = Rc::clone(&clip);
    term.on_wait = Some(Box::new(move || {
        // While waiting, the value is on the clipboard and the vault is closed.
        assert_eq!(state.borrow().contents.as_deref(), Some("EXAMPLE-copy-pw"));
        seen.set(holm_platform::lock::acquire(&folder).is_ok());
    }));
    let ran = run_env(
        &path,
        &["get", &login, "--copy", "password"],
        &mut term,
        &env,
    );
    ok(&ran);
    assert_eq!(
        term.prompts,
        vec![
            (Kind::Secret, "Master password: ".to_owned()),
            (Kind::Wait, "30".to_owned()),
        ]
    );
    assert!(lock_free.get(), "the vault lock was held during the wait");
    assert_eq!(clip.borrow().contents, None);
    assert_eq!(clip.borrow().clears, 1);
    assert!(ran.err.contains("Clipboard cleared"), "{}", ran.err);
    assert!(!ran.out.contains("EXAMPLE") && !ran.err.contains("EXAMPLE"));

    // Another app copied something meanwhile: Holm leaves it alone.
    let clip = Rc::new(RefCell::new(ClipState {
        replaced_by: Some("someone else's text".to_owned()),
        ..ClipState::default()
    }));
    let env = env_with_clip(&clip);
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run_env(
        &path,
        &["get", &login, "--copy", "username"],
        &mut term,
        &env,
    );
    ok(&ran);
    assert_eq!(clip.borrow().clears, 0);
    assert_eq!(
        clip.borrow().contents.as_deref(),
        Some("someone else's text")
    );
    assert!(ran.err.contains("left it alone"), "{}", ran.err);

    // `gen --copy` needs no vault and waits the default 30 seconds.
    let clip = Rc::new(RefCell::new(ClipState::default()));
    let env = env_with_clip(&clip);
    let mut term = FakeTerminal::new(&[]);
    let ran = run_env(&path, &["gen", "--copy"], &mut term, &env);
    ok(&ran);
    assert_eq!(ran.out, "");
    assert_eq!(term.prompts, vec![(Kind::Wait, "30".to_owned())]);
    assert_eq!(clip.borrow().sets, 1);
    assert_eq!(clip.borrow().contents, None);

    // No clipboard on this system: fixed text and exit 1, before any prompt.
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run_env(
        &path,
        &["get", &login, "--copy", "password"],
        &mut term,
        &env_no_clip(),
    );
    failed(&ran);
    assert!(ran.err.contains(&CliError::NoClipboard.to_string()));
    assert!(term.prompts.is_empty());
}

fn env_no_clip() -> holm_cli::Env {
    env()
}

#[test]
fn copy_enter_clears_now() {
    let (_dir, path) = vault_dir();
    init(&path);
    let mut term = FakeTerminal::new(&[PW, "EXAMPLE-0xenter", ""]);
    let crypto = added(&run(&path, &["add", "crypto", "--title", "W"], &mut term));

    let clip = Rc::new(RefCell::new(ClipState::default()));
    let env = env_with_clip(&clip);
    let mut term = FakeTerminal::new(&[PW]);
    term.wait_answer = true;
    let ran = run_env(
        &path,
        &["get", &crypto, "--copy", "address"],
        &mut term,
        &env,
    );
    ok(&ran);
    assert_eq!(clip.borrow().sets, 1);
    assert_eq!(clip.borrow().clears, 1);
    assert_eq!(clip.borrow().contents, None);
    assert!(ran.err.contains("Clipboard cleared"));

    // An empty field, or one the type lacks, copies nothing.
    for field in ["memo", "password"] {
        let mut term = FakeTerminal::new(&[PW]);
        let ran = run_env(&path, &["get", &crypto, "--copy", field], &mut term, &env);
        failed(&ran);
    }
    assert_eq!(clip.borrow().sets, 1);
}

#[test]
fn copy_phrase_asks_password_again() {
    let (_dir, path) = vault_dir();
    init(&path);
    let phrase = add_phrase(&path, "example copy00 copy01 copy02");

    let clip = Rc::new(RefCell::new(ClipState::default()));
    let env = env_with_clip(&clip);
    let mut term = FakeTerminal::new(&[PW, "wrong-EXAMPLE"]);
    let ran = run_env(
        &path,
        &["get", &phrase, "--copy", "phrase"],
        &mut term,
        &env,
    );
    failed(&ran);
    assert_eq!(term.kinds(), vec![Kind::Secret, Kind::Secret]);
    assert!(ran.err.contains(&CliError::WrongPassword.to_string()));
    assert_eq!(clip.borrow().sets, 0);

    let mut term = FakeTerminal::new(&[PW, PW]);
    term.on_wait = Some(Box::new({
        let state = Rc::clone(&clip);
        move || {
            assert_eq!(
                state.borrow().contents.as_deref(),
                Some("example copy00 copy01 copy02")
            );
        }
    }));
    let ran = run_env(
        &path,
        &["get", &phrase, "--copy", "phrase"],
        &mut term,
        &env,
    );
    ok(&ran);
    assert_eq!(term.kinds(), vec![Kind::Secret, Kind::Secret, Kind::Wait]);
    assert_eq!(term.prompts[1].1, "Master password again: ");
    assert_eq!(clip.borrow().sets, 1);

    // The wrong second password counts against the throttle.
    let mut s = session(&path);
    let id = id_of(&s, &phrase);
    let mut term = FakeTerminal::new(&["wrong-EXAMPLE"]);
    let e = value_of(&mut s, id, CopyField::Phrase, &mut term).unwrap_err();
    assert!(matches!(e, CliError::WrongPassword));
    assert_eq!(s.throttle_status().consecutive_failures, 1);
}

#[test]
fn no_command_output_holds_a_secret() {
    const CANARIES: [&str; 8] = [
        "CANARY-pw-7q",
        "CANARY-notes-8r",
        "CANARY-addr-9s",
        "CANARY-memo-1t",
        "CANARY phrase words 2u",
        "CANARY-body-3v",
        "CANARY-newpw-4w",
        "Canary-master-EXAMPLE-5x-strong-phrase",
    ];
    let (dir, path) = vault_dir();
    init(&path);
    let clip = Rc::new(RefCell::new(ClipState::default()));
    let env = env_with_clip(&clip);
    let mut all = String::new();
    let mut go = |args: &[&str], answers: &[&str]| -> Ran {
        let mut term = FakeTerminal::new(answers);
        let ran = run_env(&path, args, &mut term, &env);
        all.push_str(&ran.out);
        all.push_str(&ran.err);
        ran
    };
    let login = added(&go(
        &["add", "login", "--title", "L", "--with-notes"],
        &[PW, CANARIES[0], CANARIES[0], CANARIES[1]],
    ));
    let crypto = added(&go(
        &["add", "crypto", "--title", "C", "--chain", "X"],
        &[PW, CANARIES[2], CANARIES[3]],
    ));
    let phrase = added(&go(
        &["add", "phrase", "--title", "P"],
        &[PW, CANARIES[4], CANARIES[4]],
    ));
    let note = added(&go(&["add", "note", "--title", "N"], &[PW, CANARIES[5]]));
    // Mismatched and too-weak entries are not echoed back either.
    go(
        &["add", "login", "--title", "M"],
        &[PW, CANARIES[0], CANARIES[6]],
    );
    go(&["list"], &[PW]);
    for id in [&login, &crypto, &phrase, &note] {
        go(&["get", id], &[PW]);
    }
    for (id, field) in [
        (&login, "password"),
        (&login, "notes"),
        (&crypto, "address"),
        (&crypto, "memo"),
        (&note, "body"),
    ] {
        ok(&go(&["get", id, "--copy", field], &[PW]));
    }
    ok(&go(&["get", &phrase, "--copy", "phrase"], &[PW, PW]));
    ok(&go(
        &["edit", &login, "--new-password"],
        &[PW, CANARIES[6], CANARIES[6]],
    ));
    let csv = dir.path().join("out.csv");
    let csv_str = csv.to_str().unwrap();
    ok(&go(&["export", csv_str], &[PW, "export", PW]));
    let backup = dir.path().join("backup.holm");
    ok(&go(
        &["export", "--backup", backup.to_str().unwrap()],
        &[PW],
    ));
    ok(&go(&["passwd"], &[PW, PW, CANARIES[7], CANARIES[7]]));

    let (_dir2, path2) = vault_dir();
    init(&path2);
    let mut term = FakeTerminal::new(&[PW, "import"]);
    let ran = run_env(&path2, &["import", csv_str], &mut term, &env);
    ok(&ran);
    all.push_str(&ran.out);
    all.push_str(&ran.err);

    for canary in CANARIES {
        assert!(!all.contains(canary), "{canary} was printed");
    }
    assert!(!all.contains(PW));
    // The canaries really were stored and copied.
    assert!(std::fs::read_to_string(&csv).unwrap().contains(CANARIES[2]));
    assert_eq!(clip.borrow().sets, 6);
}
