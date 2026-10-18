//! `holm init`, `list`, `get` and `gen` against a vault in a temporary folder, with a
//! fake terminal.

mod common;

use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use common::{FakeTerminal, Kind, PW, init, run, session, usage, vault_dir};
use holm_cli::CliError;
use holm_cli::vault::match_reference;
use holm_core::item::{ItemData, ItemId, ItemInput};
use holm_core::text::{GatedSecret, SecretText, Text};

fn t(s: &str) -> Text {
    Text::new(s.to_owned())
}

fn st(s: &str) -> SecretText {
    SecretText::new(s.to_owned())
}

fn login(title: &str, user: &str, url: &str) -> ItemInput {
    ItemInput {
        title: t(title),
        category: None,
        favourite: false,
        data: ItemData::Login {
            username: t(user),
            password: st("EXAMPLE-pw-1"),
            urls: vec![t(url)],
            notes: st("EXAMPLE-note"),
        },
    }
}

/// The 8-hex id prefixes in `list` output, in order.
fn prefixes(out: &str) -> Vec<String> {
    out.lines()
        .map(|l| l.split('\t').next().unwrap().to_owned())
        .collect()
}

/// The titles (third column) in `list` output, in order.
fn titles(out: &str) -> Vec<String> {
    out.lines()
        .map(|l| l.split('\t').nth(2).unwrap().to_owned())
        .collect()
}

#[test]
fn init_then_list_empty() {
    let (_dir, path) = vault_dir();
    let mut term = FakeTerminal::new(&[PW, PW]);
    let ran = run(&path, &["init"], &mut term);
    assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.err);
    assert!(path.is_file());
    assert_eq!(
        term.prompts.iter().map(|p| p.0).collect::<Vec<_>>(),
        vec![Kind::Secret, Kind::Secret]
    );

    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["list"], &mut term);
    assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.err);
    assert_eq!(ran.out, "");
    assert_eq!(
        term.prompts,
        vec![(Kind::Secret, "Master password: ".to_owned())]
    );
}

#[test]
fn init_refuses_weak_and_mismatched() {
    let (_dir, path) = vault_dir();
    let mut term = FakeTerminal::new(&["password1", "password1"]);
    let ran = run(&path, &["init"], &mut term);
    assert_eq!(ran.code, ExitCode::FAILURE);
    assert!(ran.err.contains("too easy to guess"), "{}", ran.err);
    assert!(!ran.err.contains("password1") && !ran.out.contains("password1"));
    // Refused before the second prompt: no point confirming a weak password.
    assert_eq!(term.prompts.len(), 1);
    assert!(!path.exists());

    let mut term = FakeTerminal::new(&[PW, "correct-Horse-battery-staple-EXAMPLE-8"]);
    let ran = run(&path, &["init"], &mut term);
    assert_eq!(ran.code, ExitCode::FAILURE);
    assert!(ran.err.contains("don't match"), "{}", ran.err);
    assert!(!ran.err.contains("EXAMPLE"));
    assert!(!path.exists());

    // No terminal: a fixed message, nothing made.
    let mut term = FakeTerminal::new(&[]);
    let ran = run(&path, &["init"], &mut term);
    assert_eq!(ran.code, ExitCode::FAILURE);
    assert!(!path.exists());
}

#[test]
fn init_refuses_existing_vault() {
    let (_dir, path) = vault_dir();
    init(&path);
    let before = fs::read(&path).unwrap();
    let mut term = FakeTerminal::new(&[PW, PW]);
    let ran = run(&path, &["init"], &mut term);
    assert_eq!(ran.code, ExitCode::FAILURE);
    assert!(ran.err.contains("already exists"), "{}", ran.err);
    assert!(term.prompts.is_empty(), "asked for a password first");
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn list_search_filters_and_sorts() {
    let (_dir, path) = vault_dir();
    init(&path);
    {
        let mut s = session(&path);
        let work = s.add_category("Clients").unwrap();
        let mut alpha = login("Alpha mail", "ann", "https://alpha.example");
        alpha.category = Some(work);
        s.add_item(alpha).unwrap();
        // A later `created` time for the sort test.
        thread::sleep(Duration::from_millis(1100));
        let mut zeta = login("Zeta bank", "zed", "https://zeta.example");
        zeta.favourite = true;
        s.add_item(zeta).unwrap();
        s.add_item(ItemInput {
            title: t("Cold wallet"),
            category: None,
            favourite: false,
            data: ItemData::CryptoAddress {
                chain: t("Bitcoin"),
                address: st("EXAMPLE-address"),
                memo: st("EXAMPLE-memo"),
                notes: st("EXAMPLE-cnote"),
            },
        })
        .unwrap();
        let gone = s
            .add_item(login("Old forum", "olga", "https://old.example"))
            .unwrap();
        s.trash(gone).unwrap();
        s.lock();
    }

    let list = |args: &[&str]| {
        let mut full = vec!["list"];
        full.extend_from_slice(args);
        let mut term = FakeTerminal::new(&[PW]);
        let ran = run(&path, &full, &mut term);
        assert_eq!(ran.code, ExitCode::SUCCESS, "{args:?}: {}", ran.err);
        ran.out
    };

    let all = list(&[]);
    assert_eq!(titles(&all), ["Alpha mail", "Cold wallet", "Zeta bank"]);
    let first = all.lines().next().unwrap();
    let cols: Vec<&str> = first.split('\t').collect();
    assert_eq!(cols.len(), 4);
    assert_eq!(cols[0].len(), 8);
    assert!(cols[0].bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(cols[1], "login");
    assert_eq!(cols[3], "ann");
    assert!(all.contains("crypto\tCold wallet\tBitcoin"));

    assert_eq!(titles(&list(&["--search", "ZETA"])), ["Zeta bank"]);
    assert_eq!(
        titles(&list(&["--search", "alpha.example"])),
        ["Alpha mail"]
    );
    assert_eq!(titles(&list(&["--type", "crypto"])), ["Cold wallet"]);
    assert_eq!(titles(&list(&["--favourites"])), ["Zeta bank"]);
    assert_eq!(titles(&list(&["--trash"])), ["Old forum"]);
    assert_eq!(titles(&list(&["--category", " CLIENTS "])), ["Alpha mail"]);
    assert_eq!(
        titles(&list(&["--uncategorised"])),
        ["Cold wallet", "Zeta bank"]
    );
    assert_eq!(
        titles(&list(&["--type", "login", "--sort", "created"])),
        ["Zeta bank", "Alpha mail"]
    );
    assert_eq!(
        titles(&list(&["--type", "login", "--sort", "updated"])),
        ["Zeta bank", "Alpha mail"]
    );
    assert_eq!(
        titles(&list(&["--type", "login", "--sort", "title"])),
        ["Alpha mail", "Zeta bank"]
    );
    assert_eq!(prefixes(&list(&["--search", "nothing-matches"])).len(), 0);

    // An unknown category is a failure with fixed text, not an empty list.
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["list", "--category", "Holidays"], &mut term);
    assert_eq!(ran.code, ExitCode::FAILURE);
    assert!(ran.err.contains("No category"), "{}", ran.err);
    assert!(!ran.err.contains("Holidays"));

    // No secret reaches the list.
    for canary in [
        "EXAMPLE-pw-1",
        "EXAMPLE-note",
        "EXAMPLE-address",
        "EXAMPLE-memo",
    ] {
        assert!(!all.contains(canary));
    }
}

#[test]
fn get_prints_no_secret_field() {
    let (_dir, path) = vault_dir();
    init(&path);
    let ids = {
        let mut s = session(&path);
        let mut ids = vec![
            s.add_item(login("Mail", "ann", "https://mail.example"))
                .unwrap(),
        ];
        ids.push(
            s.add_item(ItemInput {
                title: t("Wallet"),
                category: None,
                favourite: true,
                data: ItemData::CryptoAddress {
                    chain: t("Bitcoin"),
                    address: st("EXAMPLE-address"),
                    memo: st("EXAMPLE-memo"),
                    notes: st("EXAMPLE-cnote"),
                },
            })
            .unwrap(),
        );
        ids.push(
            s.add_item(ItemInput {
                title: t("Seed"),
                category: None,
                favourite: false,
                data: ItemData::RecoveryPhrase {
                    phrase: GatedSecret::new(st("EXAMPLE-phrase words here")),
                    notes: st("EXAMPLE-pnote"),
                },
            })
            .unwrap(),
        );
        ids.push(
            s.add_item(ItemInput {
                title: t("Diary"),
                category: None,
                favourite: false,
                data: ItemData::SecureNote {
                    body: st("EXAMPLE-body"),
                },
            })
            .unwrap(),
        );
        s.trash(ids[3]).unwrap();
        s.lock();
        ids
    };

    let mut outputs = String::new();
    for id in &ids {
        let reference = id.to_hex();
        let mut term = FakeTerminal::new(&[PW]);
        let ran = run(&path, &["get", &reference], &mut term);
        assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.err);
        assert!(ran.out.contains("(hidden)"), "{}", ran.out);
        outputs.push_str(&ran.out);
        outputs.push_str(&ran.err);
    }
    assert!(outputs.contains("title: Mail"));
    assert!(outputs.contains("username: ann"));
    assert!(outputs.contains("url: https://mail.example"));
    assert!(outputs.contains("chain: Bitcoin"));
    assert!(outputs.contains("favourite: yes"));
    assert!(outputs.contains("in trash: yes"));
    assert!(outputs.contains("password: (hidden)"));
    assert!(outputs.contains("address: (hidden)"));
    assert!(outputs.contains("phrase: (hidden)"));
    assert!(outputs.contains("body: (hidden)"));
    for canary in [
        "EXAMPLE-pw-1",
        "EXAMPLE-note",
        "EXAMPLE-address",
        "EXAMPLE-memo",
        "EXAMPLE-cnote",
        "EXAMPLE-phrase",
        "EXAMPLE-pnote",
        "EXAMPLE-body",
        PW,
    ] {
        assert!(!outputs.contains(canary), "{canary} leaked");
    }
    // Never a length: "(hidden)" is the whole value, whatever the secret's size.
    for line in outputs.lines().filter(|l| l.contains("(hidden)")) {
        assert!(line.ends_with(": (hidden)"), "{line}");
    }
}

#[test]
fn ref_prefix_rules() {
    let (_dir, path) = vault_dir();
    init(&path);
    let id = {
        let mut s = session(&path);
        let id = s
            .add_item(login("Mail", "ann", "https://mail.example"))
            .unwrap();
        s.lock();
        id
    };
    let hex = id.to_hex();

    // Five hex digits are too short: a usage error before any prompt.
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["get", &hex[..5]], &mut term);
    assert_eq!(ran.code, usage());
    assert!(term.prompts.is_empty());
    // Upper case, or not hex at all, is a usage error too. The last digit is an
    // upper-case letter, so the ref has upper case even when the id's first digits
    // are all 0-9.
    for bad in [
        format!("{}F", hex[..7].to_uppercase()),
        "zzzzzzzz".to_owned(),
        format!("{hex}0"),
    ] {
        let mut term = FakeTerminal::new(&[PW]);
        assert_eq!(run(&path, &["get", &bad], &mut term).code, usage());
    }

    // A unique 6-digit prefix finds the item.
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["get", &hex[..6]], &mut term);
    assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.err);
    assert!(ran.out.contains("title: Mail"));

    // No match.
    let other = if hex.starts_with('0') {
        "111111"
    } else {
        "000000"
    };
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["get", other], &mut term);
    assert_eq!(ran.code, ExitCode::FAILURE);
    assert!(ran.err.contains("No item"), "{}", ran.err);

    // A shared prefix is ambiguous. Random ids can't be made to share one, so the
    // matcher is checked on its own.
    let a = ItemId::from_hex("abcdef00000000000000000000000001").unwrap();
    let b = ItemId::from_hex("abcdef00000000000000000000000002").unwrap();
    let c = ItemId::from_hex("12345600000000000000000000000003").unwrap();
    assert!(matches!(
        match_reference("abcdef", [a, b, c]),
        Err(CliError::Ambiguous { count: 2 })
    ));
    assert_eq!(
        match_reference("abcdef0000000000000000000000000", [a, b, c]).ok(),
        None
    );
    assert_eq!(
        match_reference("abcdef00000000000000000000000002", [a, b, c]).ok(),
        Some(b)
    );
    assert_eq!(match_reference("123456", [a, b, c]).ok(), Some(c));
    assert!(matches!(
        match_reference("999999", [a, b, c]),
        Err(CliError::NotFound)
    ));
    assert!(matches!(
        match_reference("abcde", [a, b, c]),
        Err(CliError::Usage(_))
    ));
}

#[test]
fn three_wrong_passwords_then_exit() {
    let (_dir, path) = vault_dir();
    init(&path);
    let wrong = "wrong-Horse-battery-staple-EXAMPLE-0";
    let mut term = FakeTerminal::new(&[wrong, wrong, wrong, wrong, PW]);
    let ran = run(&path, &["list"], &mut term);
    assert_eq!(ran.code, ExitCode::FAILURE);
    assert_eq!(term.prompts.len(), 3);
    assert_eq!(term.unused(), 2);
    assert!(ran.err.contains("didn't open this vault"), "{}", ran.err);
    assert!(!ran.err.contains("EXAMPLE"));
}

#[test]
fn second_instance_refused_before_prompt() {
    let (dir, path) = vault_dir();
    init(&path);
    let _held = holm_platform::lock::acquire(dir.path()).unwrap();
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["list"], &mut term);
    assert_eq!(ran.code, ExitCode::FAILURE);
    assert!(ran.err.contains("already open"), "{}", ran.err);
    assert!(term.prompts.is_empty());
}

#[test]
fn no_vault_fails_before_prompt() {
    let (_dir, path) = vault_dir();
    let mut term = FakeTerminal::new(&[PW]);
    let ran = run(&path, &["list"], &mut term);
    assert_eq!(ran.code, ExitCode::FAILURE);
    assert!(ran.err.contains("no vault"), "{}", ran.err);
    assert!(term.prompts.is_empty());
    assert!(!ran.err.contains(path.to_str().unwrap()));
}

#[test]
fn gen_needs_no_vault() {
    let (_dir, path) = vault_dir();
    for (kind, check) in [("password", 20_usize), ("passphrase", 10), ("username", 3)] {
        let mut term = FakeTerminal::new(&[]);
        let ran = run(&path, &["gen", kind], &mut term);
        assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.err);
        assert!(ran.out.trim_end().len() >= check, "{kind}");
        assert!(ran.out.ends_with('\n'));
        assert!(term.prompts.is_empty());
    }
    let mut term = FakeTerminal::new(&[]);
    let a = run(&path, &["gen"], &mut term).out;
    let b = run(&path, &["gen"], &mut term).out;
    assert_ne!(a, b);
    assert!(!path.exists());
}

/// Secrets come only from the terminal. No source file in the CLI, nor the terminal
/// module, reads an environment variable or the standard input stream, and `main.rs`
/// touches the environment only for its arguments.
#[test]
fn env_is_never_read_for_secrets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![root.join("../holm-platform/src/tty.rs")];
    let mut dirs = vec![root.join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    assert!(files.len() >= 8, "found only {} files", files.len());
    for file in files {
        let text = fs::read_to_string(&file).unwrap();
        for banned in ["env::var", "var_os", "io::stdin", "stdin()", "Stdin"] {
            assert!(
                !text.contains(banned),
                "{} contains {banned}",
                file.display()
            );
        }
        let is_main = file.file_name().is_some_and(|n| n == "main.rs");
        for (at, _) in text.match_indices("env::") {
            assert!(
                is_main && text[at..].starts_with("env::args_os()"),
                "{} uses env:: other than args_os in main.rs",
                file.display()
            );
        }
    }
}
