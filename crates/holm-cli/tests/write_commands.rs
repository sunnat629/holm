#![forbid(unsafe_code)]
//! `holm add`, `edit`, `rm`, `passwd` and `--copy` against a vault in a temporary
//! folder, with a fake terminal and a fake clipboard.

mod common;

use std::cell::{Cell, RefCell};
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::rc::Rc;

use common::{
    ClipState, FakeClip, FakeTerminal, Kind, PW, Ran, env, env_with_clip, init, run, run_env,
    session, usage, vault_dir,
};
use holm_cli::CliError;
use holm_cli::args::{Command, CopyField};
use holm_cli::commands::copy::{copy_and_wait, value_of};
use holm_cli::output::write_error;
use holm_core::error::CoreError;
use holm_core::fields::{
    CustomField, FieldKind, FieldPreset, FieldValue, move_field, preset_fields, remove_field,
    try_field,
};
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
        fields: Vec::new(),
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

    // A wrong current password changes nothing and stops before the new prompt.
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
fn passwd_checks_current_first() {
    let (_dir, path) = vault_dir();
    init(&path);
    let before = std::fs::read(&path).unwrap();
    let mut term = FakeTerminal::new(&[PW, "wrong-EXAMPLE"]);
    let ran = run(&path, &["passwd"], &mut term);
    failed(&ran);
    assert!(ran.err.contains(&CliError::WrongPassword.to_string()));
    assert_eq!(term.prompts.len(), 2);
    assert_eq!(term.prompts[1].1, "Current master password: ");
    assert_eq!(std::fs::read(&path).unwrap(), before);
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

    // The clipboard can't be read back: Holm clears it anyway and says so.
    let clip = Rc::new(RefCell::new(ClipState {
        unreadable_checks: 1,
        ..ClipState::default()
    }));
    let env = env_with_clip(&clip);
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run_env(
        &path,
        &["get", &login, "--copy", "password"],
        &mut term,
        &env,
    );
    ok(&ran);
    assert_eq!(clip.borrow().clears, 1);
    assert_eq!(clip.borrow().contents, None);
    assert!(
        ran.err
            .contains("Holm couldn't read the clipboard to check it, so it cleared it anyway."),
        "{}",
        ran.err
    );
    assert!(!ran.err.contains("left it alone"), "{}", ran.err);

    // Not even after the clear: Holm says it could not check.
    let clip = Rc::new(RefCell::new(ClipState {
        unreadable_checks: 2,
        ..ClipState::default()
    }));
    let env = env_with_clip(&clip);
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run_env(
        &path,
        &["get", &login, "--copy", "password"],
        &mut term,
        &env,
    );
    ok(&ran);
    assert_eq!(clip.borrow().clears, 1);
    assert_eq!(clip.borrow().contents, None);
    assert!(
        ran.err.contains(
            "Holm cleared the clipboard but couldn't read it back to check that it's empty."
        ),
        "{}",
        ran.err
    );

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
fn copy_wait_is_clamped_to_the_shared_range() {
    for (asked, waited) in [(0_u32, "5"), (u32::MAX, "90"), (30, "30")] {
        let clip = Rc::new(RefCell::new(ClipState::default()));
        let mut term = FakeTerminal::new(&[]);
        let mut err = Vec::new();
        copy_and_wait(
            zeroize::Zeroizing::new("EXAMPLE-clamp".to_owned()),
            asked,
            &mut FakeClip(Rc::clone(&clip)),
            &mut term,
            &mut err,
            &holm_core::clock::SystemClock::new(),
        )
        .expect("copy");
        assert_eq!(term.prompts, vec![(Kind::Wait, waited.to_owned())]);
        let said = String::from_utf8(err).expect("utf8");
        assert!(said.contains(&format!("in {waited} seconds")), "{said}");
    }
}

/// A sleep during the one-shot copy wait clears the clipboard on wake: the wait polls
/// the pending clear, whose wall-clock deadline passed while the Mac slept, so it ends
/// with no key press and the value is cleared once.
#[test]
fn copy_wait_ends_on_wake_after_sleep() {
    let clip = Rc::new(RefCell::new(ClipState::default()));
    let clock = common::TestClock::new();
    let mut term = FakeTerminal::new(&[]);
    term.wait_stalls = true;
    let asleep = clock.clone();
    // Ninety-one seconds asleep, past the longest clear time, with no key pressed.
    term.on_wait = Some(Box::new(move || asleep.sleep(91)));
    let mut err = Vec::new();
    copy_and_wait(
        zeroize::Zeroizing::new("EXAMPLE-sleep".to_owned()),
        90,
        &mut FakeClip(Rc::clone(&clip)),
        &mut term,
        &mut err,
        &clock,
    )
    .expect("copy");
    assert_eq!(term.wait_interrupted, 1, "the interrupt ended the wait");
    assert_eq!(clip.borrow().sets, 1);
    assert_eq!(clip.borrow().clears, 1);
    assert_eq!(clip.borrow().contents, None);
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

fn text_field(label: &str, value: &str) -> CustomField {
    try_field(
        Text::new(label.to_owned()),
        FieldValue::Text(Text::new(value.to_owned())),
        None,
    )
    .unwrap()
}

fn secret_field(label: &str, value: &str) -> CustomField {
    try_field(
        Text::new(label.to_owned()),
        FieldValue::Secret(SecretText::new(value.to_owned())),
        None,
    )
    .unwrap()
}

fn login_input(title: &str, fields: Vec<CustomField>) -> ItemInput {
    ItemInput {
        fields,
        title: Text::new(title.to_owned()),
        category: None,
        favourite: false,
        data: ItemData::Login {
            username: Text::new("me".to_owned()),
            password: SecretText::new("EXAMPLE-pw-1".to_owned()),
            urls: Vec::new(),
            notes: SecretText::new(String::new()),
        },
    }
}

fn prefix_of(path: &Path, input: ItemInput) -> String {
    let mut s = session(path);
    let hex = s.add_item(input).unwrap().to_hex();
    hex[..8].to_owned()
}

fn kinds_of(fields: &[CustomField]) -> Vec<(String, FieldKind)> {
    fields
        .iter()
        .map(|field| (field.label().to_owned(), field.kind()))
        .collect()
}

fn value_empty(field: &CustomField) -> bool {
    match field.value() {
        FieldValue::Text(text) => text.as_str().is_empty(),
        FieldValue::Secret(text) | FieldValue::MultilineSecret(text) => text.expose().is_empty(),
        FieldValue::Date(_) => false,
        FieldValue::RecoveryCodes(codes) => codes.is_empty(),
    }
}

#[test]
fn copy_custom_does_not_print_the_secret() {
    const SECRET: &str = "EXAMPLE-field-secret";
    let (_dir, path) = vault_dir();
    init(&path);
    let id = prefix_of(
        &path,
        login_input("Mail", vec![secret_field("API token", SECRET)]),
    );
    let clip = Rc::new(RefCell::new(ClipState::default()));
    let env = env_with_clip(&clip);
    let mut term = FakeTerminal::new(&[PW]);
    term.on_wait = Some(Box::new({
        let state = Rc::clone(&clip);
        move || assert_eq!(state.borrow().contents.as_deref(), Some(SECRET))
    }));
    let ran = run_env(&path, &["get", &id, "--copy", "field=1"], &mut term, &env);
    ok(&ran);
    assert!(!ran.out.contains(SECRET));
    assert!(!ran.err.contains(SECRET));
    assert_eq!(term.kinds(), vec![Kind::Secret, Kind::Wait]);
    assert_eq!(term.prompts[0].1, "Master password: ");
    assert!(
        term.prompts
            .iter()
            .all(|prompt| prompt.1 != "Master password again: ")
    );
    assert!(clip.borrow().contents.is_none());
    assert_eq!(clip.borrow().sets, 1);
    assert_eq!(clip.borrow().clears, 1);
}

#[test]
fn copy_custom_empty_is_an_error() {
    let (_dir, path) = vault_dir();
    init(&path);
    let id = prefix_of(&path, login_input("Mail", vec![text_field("Note", "")]));
    let clip = Rc::new(RefCell::new(ClipState::default()));
    let env = env_with_clip(&clip);

    let mut term = FakeTerminal::new(&[PW]);
    let ran = run_env(&path, &["get", &id, "--copy", "field=1"], &mut term, &env);
    failed(&ran);
    assert!(ran.err.contains("That field is empty"));
    assert_eq!(term.kinds(), vec![Kind::Secret]);
    assert_eq!(clip.borrow().sets, 0);

    let mut term = FakeTerminal::new(&[PW]);
    let ran = run_env(&path, &["get", &id, "--copy", "field=2"], &mut term, &env);
    failed(&ran);
    assert!(ran.err.contains("no such field"));
    assert_eq!(clip.borrow().sets, 0);
}

#[test]
fn add_preset_empty_values() {
    let (_dir, path) = vault_dir();
    init(&path);
    let mut term = FakeTerminal::new(&[PW, "EXAMPLE-pw-1", "EXAMPLE-pw-1"]);
    let ran = run(
        &path,
        &["add", "login", "--title", "Mail", "--preset", "server"],
        &mut term,
    );
    let id = added(&ran);
    assert!(ran.out.contains("Added 5 custom fields with empty values."));
    assert!(
        term.prompts
            .iter()
            .all(|prompt| prompt.1 != "Field value: ")
    );
    assert_eq!(term.kinds(), vec![Kind::Secret, Kind::Secret, Kind::Secret]);
    let s = session(&path);
    let fields = s.item(id_of(&s, &id)).unwrap().fields();
    assert_eq!(fields.len(), preset_fields(FieldPreset::Server).len());
    for (field, row) in fields.iter().zip(preset_fields(FieldPreset::Server)) {
        assert_eq!(field.label(), row.label);
        assert_eq!(field.kind(), row.kind);
        assert!(field.expiry().is_none());
        assert!(value_empty(field));
    }
    drop(s);

    let mut term = FakeTerminal::new(&[PW, "EXAMPLE-pw-1", "EXAMPLE-pw-1"]);
    let ran = run(
        &path,
        &["add", "login", "--title", "Card", "--preset", "bank-card"],
        &mut term,
    );
    let id = added(&ran);
    assert!(ran.out.contains("Added 3 custom fields with empty values."));
    let s = session(&path);
    let fields = s.item(id_of(&s, &id)).unwrap().fields();
    let rows: Vec<_> = preset_fields(FieldPreset::BankCard)
        .iter()
        .filter(|row| row.kind != FieldKind::Date)
        .collect();
    assert_eq!(fields.len(), rows.len());
    assert!(fields.iter().all(|field| field.label() != "Expiry"));
    for (field, row) in fields.iter().zip(rows) {
        assert_eq!(field.label(), row.label);
        assert_eq!(field.kind(), row.kind);
        assert!(value_empty(field));
    }
}

#[test]
fn add_preset_recovery_codes_prompts_hidden() {
    const CODES: &str = "EXAMPLE-code-1\nEXAMPLE-code-2";
    let (_dir, path) = vault_dir();
    init(&path);
    let mut term = FakeTerminal::new(&[PW, "EXAMPLE-pw-1", "EXAMPLE-pw-1", CODES]);
    let ran = run(
        &path,
        &[
            "add",
            "login",
            "--title",
            "Mail",
            "--preset",
            "recovery-codes",
        ],
        &mut term,
    );
    let id = added(&ran);
    assert_eq!(term.kinds(), vec![Kind::Secret; 4]);
    assert_eq!(term.prompts[3].1, "Field value: ");
    assert!(!ran.out.contains("EXAMPLE-code") && !ran.err.contains("EXAMPLE-code"));
    assert!(!ran.out.contains("empty values"), "{}", ran.out);
    let s = session(&path);
    let fields = s.item(id_of(&s, &id)).unwrap().fields();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].label(), "Recovery codes");
    let FieldValue::RecoveryCodes(codes) = fields[0].value() else {
        panic!("not codes");
    };
    let typed: Vec<&str> = codes.iter().map(|code| code.code().expose()).collect();
    assert_eq!(typed, ["EXAMPLE-code-1", "EXAMPLE-code-2"]);
    assert!(codes.iter().all(|code| !code.used()));
    drop(s);

    // Nothing typed skips the field, as an empty preset value would be.
    let mut term = FakeTerminal::new(&[PW, "EXAMPLE-pw-1", "EXAMPLE-pw-1", ""]);
    let ran = run(
        &path,
        &[
            "add",
            "login",
            "--title",
            "Bare",
            "--preset",
            "recovery-codes",
        ],
        &mut term,
    );
    let id = added(&ran);
    assert!(!ran.out.contains("custom fields"), "{}", ran.out);
    let s = session(&path);
    assert!(s.item(id_of(&s, &id)).unwrap().fields().is_empty());
}

#[test]
fn edit_field_add_prompts_for_secret() {
    const SECRET: &str = "EXAMPLE-prompt-secret";
    let (_dir, path) = vault_dir();
    init(&path);
    let id = add_login(&path, "EXAMPLE-pw-1");
    let args = [
        "edit",
        id.as_str(),
        "--field-add",
        "API token",
        "--kind",
        "secret",
    ];
    assert!(args.iter().all(|arg| !arg.contains(SECRET)));
    let mut term = FakeTerminal::new(&[PW, SECRET]);
    let ran = run(&path, &args, &mut term);
    ok(&ran);
    assert!(
        term.prompts
            .iter()
            .any(|prompt| prompt.0 == Kind::Secret && prompt.1 == "Field value: ")
    );
    assert!(!ran.out.contains(SECRET));
    assert!(!ran.err.contains(SECRET));
    let s = session(&path);
    let field = &s.item(id_of(&s, &id)).unwrap().fields()[0];
    assert_eq!(field.label(), "API token");
    let FieldValue::Secret(value) = field.value() else {
        panic!("not a secret");
    };
    assert_eq!(value.expose(), SECRET);
}

#[test]
fn secret_value_rejected_on_command_line() {
    let (_dir, path) = vault_dir();
    init(&path);
    let before = fs::read(&path).unwrap();
    let lines: &[&[&str]] = &[
        &[
            "edit",
            "abcdef",
            "--field-add",
            "Token",
            "--kind",
            "secret",
            "--value",
            "EXAMPLE",
        ],
        &[
            "edit",
            "abcdef",
            "--field-add",
            "Token",
            "--value",
            "EXAMPLE",
            "--kind",
            "secret",
        ],
        &[
            "edit",
            "abcdef",
            "--field-add",
            "Token",
            "--kind",
            "multiline",
            "--value",
            "EXAMPLE",
        ],
    ];
    for line in lines {
        let mut term = FakeTerminal::new(&[]);
        let ran = run(&path, line, &mut term);
        assert_eq!(ran.code, usage());
        assert!(
            ran.err
                .contains("A secret is typed at the prompt, not on the command line.")
        );
        assert!(!ran.err.contains("EXAMPLE"));
        assert!(!ran.out.contains("EXAMPLE"));
        assert!(term.prompts.is_empty());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn edit_field_remove_and_move() {
    let (_dir, path) = vault_dir();
    init(&path);
    let id = prefix_of(
        &path,
        login_input(
            "Box",
            vec![
                text_field("One", "1"),
                text_field("Two", "2"),
                text_field("Three", "3"),
            ],
        ),
    );
    let mut parallel = vec![
        text_field("One", "1"),
        text_field("Two", "2"),
        text_field("Three", "3"),
    ];
    move_field(&mut parallel, 2, 0).unwrap();

    let mut term = FakeTerminal::new(&[PW]);
    ok(&run(
        &path,
        &["edit", &id, "--field-move", "3", "--to", "1"],
        &mut term,
    ));
    let s = session(&path);
    assert_eq!(
        kinds_of(s.item(id_of(&s, &id)).unwrap().fields()),
        kinds_of(&parallel)
    );
    drop(s);

    remove_field(&mut parallel, 1).unwrap();
    let mut term = FakeTerminal::new(&[PW]);
    ok(&run(
        &path,
        &["edit", &id, "--field-remove", "2"],
        &mut term,
    ));
    let s = session(&path);
    assert_eq!(
        kinds_of(s.item(id_of(&s, &id)).unwrap().fields()),
        kinds_of(&parallel)
    );
}

#[test]
fn export_format_json() {
    let (dir, path) = vault_dir();
    init(&path);
    add_login(&path, "EXAMPLE-pw-1");
    let file = dir.path().join("out.json");
    let file_arg = file.to_str().unwrap();
    let mut term = FakeTerminal::new(&[PW, "export", PW]);
    let ran = run(&path, &["export", file_arg, "--format", "json"], &mut term);
    ok(&ran);
    assert_eq!(term.kinds(), vec![Kind::Secret, Kind::Line, Kind::Secret]);
    let bytes = fs::read(&file).unwrap();
    assert!(bytes.starts_with(b"["));
    let batch = holm_core::import::parse(&bytes, holm_core::import::ImportFormat::Json).unwrap();
    assert!(batch.ready() >= 1);
    assert!(batch.issues().is_empty());

    let other = dir.path().join("both.json");
    let mut term = FakeTerminal::new(&[PW, "export", PW]);
    let ran = run(
        &path,
        &[
            "export",
            other.to_str().unwrap(),
            "--format",
            "json",
            "--backup",
        ],
        &mut term,
    );
    assert_eq!(ran.code, usage());
    assert!(term.prompts.is_empty());
    assert!(!other.exists());
}

#[test]
fn args_debug_has_no_secret() {
    let edit = command(&[
        "edit",
        "abcdef",
        "--field-add",
        "EXAMPLE-label",
        "--kind",
        "text",
        "--value",
        "EXAMPLE-value",
    ]);
    let Command::Edit(edit) = edit else {
        panic!("not edit");
    };
    let shown = format!("{edit:?}");
    assert!(!shown.contains("EXAMPLE"));
    assert!(shown.contains("Text"));
    assert!(shown.contains("value_len"));

    let add = command(&[
        "add",
        "login",
        "--title",
        "EXAMPLE-title",
        "--preset",
        "server",
    ]);
    let Command::Add(add) = add else {
        panic!("not add");
    };
    let shown = format!("{add:?}");
    assert!(!shown.contains("EXAMPLE"));
    assert!(shown.contains("Server"));
}

fn command(list: &[&str]) -> Command {
    let args: Vec<OsString> = list.iter().copied().map(OsString::from).collect();
    holm_cli::args::parse(&args).unwrap().command
}
