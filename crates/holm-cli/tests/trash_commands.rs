#![forbid(unsafe_code)]
//! `holm restore`, `holm empty-trash` and `holm list --trash`.

mod common;

use std::path::Path;
use std::process::ExitCode;

use common::{FakeTerminal, Kind, PW, init, run, session, vault_dir};
use holm_core::search::{Query, View};

fn ok(ran: &common::Ran) {
    assert_eq!(
        ran.code,
        ExitCode::SUCCESS,
        "out: {}\nerr: {}",
        ran.out,
        ran.err
    );
}

fn failed(ran: &common::Ran) {
    assert_eq!(
        ran.code,
        ExitCode::FAILURE,
        "out: {}\nerr: {}",
        ran.out,
        ran.err
    );
}

/// Adds a login called `title`; returns its 8-hex prefix.
fn add(path: &Path, title: &str) -> String {
    let mut term = FakeTerminal::new(&[PW, "pw-EXAMPLE-1", "pw-EXAMPLE-1"]);
    let ran = run(path, &["add", "login", "--title", title], &mut term);
    ok(&ran);
    ran.out
        .lines()
        .last()
        .unwrap()
        .strip_prefix("Added ")
        .and_then(|l| l.strip_suffix('.'))
        .unwrap()
        .to_owned()
}

fn trash(path: &Path, prefix: &str) {
    let mut term = FakeTerminal::new(&[PW]);
    ok(&run(path, &["rm", prefix], &mut term));
}

fn counts(path: &Path) -> (usize, usize) {
    let s = session(path);
    let trashed = s
        .search(&Query {
            view: View::Trash,
            ..Query::default()
        })
        .unwrap()
        .len();
    (s.active_entries().unwrap().count(), trashed)
}

#[test]
fn list_trash_shows_only_trashed() {
    let (_dir, path) = vault_dir();
    init(&path);
    let _keep = add(&path, "Keeper");
    let gone = add(&path, "Goner");
    trash(&path, &gone);
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["list", "--trash"], &mut term);
    ok(&ran);
    assert!(ran.out.contains("Goner"), "{}", ran.out);
    assert!(!ran.out.contains("Keeper"), "{}", ran.out);
}

#[test]
fn restore_moves_item_back_and_saves() {
    let (_dir, path) = vault_dir();
    init(&path);
    let id = add(&path, "Goner");
    trash(&path, &id);
    assert_eq!(counts(&path), (0, 1));
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["restore", &id], &mut term);
    ok(&ran);
    assert!(ran.out.contains(&format!("Restored {id}.")), "{}", ran.out);
    assert_eq!(counts(&path), (1, 0));
}

#[test]
fn restore_refuses_active_item() {
    let (_dir, path) = vault_dir();
    init(&path);
    let id = add(&path, "Live");
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["restore", &id], &mut term);
    failed(&ran);
    assert!(ran.err.contains("isn't in the Trash"), "{}", ran.err);
    assert_eq!(counts(&path), (1, 0));
}

#[test]
fn restore_unknown_ref_is_not_found() {
    let (_dir, path) = vault_dir();
    init(&path);
    let _id = add(&path, "Live");
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["restore", "ffffffff"], &mut term);
    failed(&ran);
    assert!(!ran.err.contains("isn't in the Trash"), "{}", ran.err);
    assert!(ran.err.contains("No item matches"), "{}", ran.err);
    assert_eq!(counts(&path), (1, 0));
}

fn two_in_trash(path: &Path) {
    init(path);
    for title in ["One", "Two"] {
        let id = add(path, title);
        trash(path, &id);
    }
    assert_eq!(counts(path), (0, 2));
}

#[test]
fn empty_trash_needs_typed_word() {
    let (_dir, path) = vault_dir();
    two_in_trash(&path);
    let mut term = FakeTerminal::new(&[PW, "yes"]);
    let ran = run(&path, &["empty-trash"], &mut term);
    ok(&ran);
    assert!(ran.out.contains("Nothing deleted."), "{}", ran.out);
    assert!(
        term.prompts
            .iter()
            .any(|(k, p)| *k == Kind::Line && p.contains("Type empty to delete 2 items forever:")),
        "{:?}",
        term.prompts
    );
    assert_eq!(counts(&path), (0, 2));

    let mut term = FakeTerminal::new(&[PW, "empty"]);
    let ran = run(&path, &["empty-trash"], &mut term);
    ok(&ran);
    assert!(ran.out.contains("Deleted 2 items forever."), "{}", ran.out);
    assert_eq!(counts(&path), (0, 0));
}

#[test]
fn empty_trash_eof_deletes_nothing() {
    let (_dir, path) = vault_dir();
    two_in_trash(&path);
    // No answer for the confirm prompt: the fake terminal reports end of input.
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["empty-trash"], &mut term);
    failed(&ran);
    assert_eq!(counts(&path), (0, 2));
}

#[test]
fn empty_trash_when_empty() {
    let (_dir, path) = vault_dir();
    init(&path);
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["empty-trash"], &mut term);
    ok(&ran);
    assert!(ran.out.contains("Trash is empty."), "{}", ran.out);
    assert_eq!(term.kinds(), [Kind::Secret]);
}

#[test]
fn shell_runs_restore_and_empty_trash() {
    let (_dir, path) = vault_dir();
    init(&path);
    let a = add(&path, "Alpha");
    let b = add(&path, "Beta");
    trash(&path, &a);
    trash(&path, &b);
    let restore = format!("restore {a}");
    let mut term = FakeTerminal::new(&[PW, &restore, "empty-trash", "empty", "exit"]);
    let ran = run(&path, &["shell"], &mut term);
    ok(&ran);
    assert!(ran.out.contains(&format!("Restored {a}.")), "{}", ran.out);
    assert!(ran.out.contains("Deleted 1 item forever."), "{}", ran.out);
    assert_eq!(counts(&path), (1, 0));
}
