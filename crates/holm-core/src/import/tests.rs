use super::*;
use crate::category::BUILT_IN_CATEGORIES;
use crate::clock::FakeClock;
use crate::envelope::VaultError;
use crate::fields::{FieldKind, FieldValue, format_date};
use crate::item::{Item, ItemData, ItemId};
use crate::rules::{Field, FieldError, MAX_ITEMS};
use crate::store::MemStore;
use crate::text::{SecretText, Text};
use holm_crypto::MasterPassword;
use holm_crypto::kdf::KdfParams;

type S = Session<MemStore>;

const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";
const NOW: i64 = 1_700_000_000;
const HEADER: &str = "title,username,password,url,notes,category,type,chain,address,memo,recovery";

const HOLM_CSV: &[u8] = include_bytes!("../../tests/fixtures/import/holm.csv");
const HOLM_JSON: &[u8] = include_bytes!("../../tests/fixtures/import/holm.json");
const CHROME_CSV: &[u8] = include_bytes!("../../tests/fixtures/import/chrome.csv");
const FIREFOX_CSV: &[u8] = include_bytes!("../../tests/fixtures/import/firefox.csv");
const SAFARI_CSV: &[u8] = include_bytes!("../../tests/fixtures/import/safari.csv");
const SPREADSHEET_CSV: &[u8] = include_bytes!("../../tests/fixtures/import/spreadsheet.csv");

const PHRASE: &str =
    "example word00 word01 word02 word03 word04 word05 word06 word07 word08 word09 word10 word11";

fn fresh() -> S {
    let clock = FakeClock::default();
    clock.set_unix(NOW);
    let mut s = Session::new(MemStore::default(), Box::new(clock));
    s.create(&MasterPassword::new(PW.to_owned()), &KdfParams::FLOOR)
        .unwrap();
    s
}

fn csv(src: &str) -> ImportBatch {
    parse(src.as_bytes(), ImportFormat::Csv).unwrap()
}

#[test]
fn import_clamps_timestamps() {
    let mut s = fresh();
    let source = format!(
        "title,type,notes,created,updated\nPast,note,example,{0},{0}\nFuture,note,example,{1},{1}\nBoth,note,example,{0},{1}\n",
        i64::MIN,
        i64::MAX
    );
    s.import(csv(&source)).unwrap();
    for (title, created, updated) in [("Past", 0, 0), ("Future", NOW, NOW), ("Both", 0, NOW)] {
        let item = by_title(&s, title);
        assert_eq!(item.created(), Timestamp(created));
        assert_eq!(item.updated(), Timestamp(updated));
    }
    for value in [i64::MIN, i64::MAX] {
        for pair in [
            times(Timestamp(NOW), Some(Timestamp(value)), None),
            times(Timestamp(NOW), None, Some(Timestamp(value))),
        ] {
            assert!((0..=NOW).contains(&pair.0.0));
            assert!((0..=NOW).contains(&pair.1.0));
            assert!(pair.0 <= pair.1);
        }
    }
    assert_eq!(
        times(Timestamp(-1), None, None),
        (Timestamp(0), Timestamp(0))
    );
}

fn json(src: &str) -> ImportBatch {
    parse(src.as_bytes(), ImportFormat::Json).unwrap()
}

fn csv_err(src: &[u8]) -> ImportError {
    parse(src, ImportFormat::Csv).unwrap_err()
}

fn json_err(src: &[u8]) -> ImportError {
    parse(src, ImportFormat::Json).unwrap_err()
}

fn issues(b: &ImportBatch) -> Vec<(usize, RowProblem)> {
    b.issues().iter().map(|i| (i.row, i.problem)).collect()
}

fn imported(src: &str) -> S {
    let mut s = fresh();
    s.import(csv(src)).unwrap();
    s
}

/// The item titled `title`. Leaked so tests can borrow it freely; test data only.
fn by_title(s: &S, title: &str) -> &'static Item {
    s.active_items()
        .unwrap()
        .find(|i| i.title() == title)
        .map(|item| &*Box::leak(Box::new(item)))
        .unwrap_or_else(|| panic!("no item titled {title}"))
}

fn titles(s: &S) -> Vec<String> {
    let mut t: Vec<String> = s
        .active_items()
        .unwrap()
        .map(|i| i.title().to_owned())
        .collect();
    t.sort();
    t
}

/// Username, password, URLs and notes of a login.
fn login_of(item: &Item) -> (&str, &str, Vec<&str>, &str) {
    match item.data() {
        ItemData::Login {
            username,
            password,
            urls,
            notes,
        } => (
            username.as_str(),
            password.expose(),
            urls.iter().map(Text::as_str).collect(),
            notes.expose(),
        ),
        _ => panic!("not a login"),
    }
}

fn category_name(s: &S, item: &Item) -> Option<String> {
    let id = item.category()?;
    s.categories()
        .unwrap()
        .iter()
        .find(|c| c.id() == id)
        .map(|c| c.name().to_owned())
}

fn category_names(s: &S) -> Vec<String> {
    s.categories()
        .unwrap()
        .iter()
        .map(|c| c.name().to_owned())
        .collect()
}

/// Checks the four items of the `holm.csv` / `holm.json` fixture.
fn check_fixture_items(s: &S) {
    assert_eq!(s.active_items().unwrap().count(), 4);

    let portal = by_title(s, "Example Portal");
    assert_eq!(
        login_of(portal),
        (
            "example.user",
            "EXAMPLE-pass-1",
            vec!["https://portal.example.com"],
            ""
        )
    );
    assert_eq!(category_name(s, portal).as_deref(), Some("Work"));

    let memo = by_title(s, "Example Memo");
    match memo.data() {
        ItemData::SecureNote { body } => assert_eq!(body.expose(), "EXAMPLE memo body"),
        _ => panic!("not a note"),
    }
    assert_eq!(category_name(s, memo).as_deref(), Some("Personal"));

    let wallet = by_title(s, "Example Wallet");
    match wallet.data() {
        ItemData::CryptoAddress {
            chain,
            address,
            memo,
            notes,
        } => {
            assert_eq!(chain.as_str(), "EXAMPLE-chain");
            assert_eq!(address.expose(), "EXAMPLE-0xaddr01");
            assert_eq!(memo.expose(), "EXAMPLE-memo");
            assert_eq!(notes.expose(), "");
        }
        _ => panic!("not crypto"),
    }
    assert_eq!(wallet.category(), None);

    let recovery = by_title(s, "Example Recovery");
    match recovery.data() {
        ItemData::RecoveryPhrase { phrase, notes } => {
            assert_eq!(phrase.expose(), PHRASE);
            assert_eq!(notes.expose(), "");
        }
        _ => panic!("not a phrase"),
    }
    for item in s.active_items().unwrap() {
        assert!(!item.favourite());
        assert_eq!(item.created(), Timestamp(NOW));
        assert_eq!(item.updated(), Timestamp(NOW));
    }
}

#[test]
fn holm_csv_all_types() {
    let batch = parse(HOLM_CSV, ImportFormat::Csv).unwrap();
    assert_eq!(batch.dialect(), Dialect::Holm);
    assert_eq!(batch.ready(), 4);
    assert!(batch.issues().is_empty());
    let mut s = fresh();
    let report = s.import(batch).unwrap();
    assert_eq!(
        report,
        ImportReport {
            imported: 4,
            uncategorised: 2,
            duplicates: 0,
            skipped: 0
        }
    );
    check_fixture_items(&s);
    assert!(!s.is_dirty());
}

#[test]
fn columns_case_insensitive_any_order_and_aliases() {
    let s = imported(concat!(
        " Recovery_Secret ,TYPE,Title\n",
        "example one two three,recovery,Seed\n",
    ));
    match by_title(&s, "Seed").data() {
        ItemData::RecoveryPhrase { phrase, .. } => {
            assert_eq!(phrase.expose(), "example one two three");
        }
        _ => panic!("not a phrase"),
    }
    let s = imported("Website,PassWord,TITLE,Phrase\nhttps://w.example.com,EXAMPLE-pw,Site,\n");
    assert_eq!(
        login_of(by_title(&s, "Site")),
        ("", "EXAMPLE-pw", vec!["https://w.example.com"], "")
    );
}

#[test]
fn spreadsheet_quirks() {
    let batch = parse(SPREADSHEET_CSV, ImportFormat::Csv).unwrap();
    assert_eq!(batch.dialect(), Dialect::Holm);
    assert_eq!(batch.ready(), 1);
    assert!(batch.issues().is_empty());
    let mut s = fresh();
    s.import(batch).unwrap();
    let item = by_title(&s, "Sheet Login");
    assert_eq!(
        login_of(item),
        (
            "sheet.user",
            "EXAMPLE-sheet-pw",
            vec!["https://sheet.example.com"],
            "line one\r\nline two"
        )
    );
    assert_eq!(category_name(&s, item).as_deref(), Some("Work"));
}

#[test]
fn one_bom_stripped_for_csv_and_json() {
    let mut with_bom = b"\xef\xbb\xbf".to_vec();
    with_bom.extend_from_slice(HOLM_CSV);
    assert_eq!(parse(&with_bom, ImportFormat::Csv).unwrap().ready(), 4);

    let mut with_bom = b"\xef\xbb\xbf".to_vec();
    with_bom.extend_from_slice(HOLM_JSON);
    assert_eq!(parse(&with_bom, ImportFormat::Json).unwrap().ready(), 4);

    // Only one is removed: a second BOM is part of the first header name or is not JSON.
    assert_eq!(
        csv_err("\u{feff}\u{feff}title,url\nT,\n".as_bytes()),
        ImportError::UnknownColumns { count: 1 }
    );
    assert_eq!(
        json_err("\u{feff}\u{feff}[]".as_bytes()),
        ImportError::Malformed { line: 1 }
    );
    // A BOM alone is an empty file.
    assert_eq!(csv_err(b"\xef\xbb\xbf"), ImportError::Empty);
    assert_eq!(json_err(b"\xef\xbb\xbf \n"), ImportError::Empty);
}

#[test]
fn file_level_errors() {
    assert_eq!(csv_err(b"title\n\xff\n"), ImportError::NotUtf8);
    assert_eq!(json_err(b"[\xff]"), ImportError::NotUtf8);
    let big = vec![b' '; MAX_IMPORT_BYTES + 1];
    assert_eq!(csv_err(&big), ImportError::TooLarge);
    assert_eq!(json_err(&big), ImportError::TooLarge);
    assert_eq!(csv_err(b"  \n"), ImportError::Empty);
    assert_eq!(csv_err(b""), ImportError::Empty);
    assert_eq!(json_err(b"\r\n\t "), ImportError::Empty);
    assert_eq!(
        csv_err(b"title,colour"),
        ImportError::UnknownColumns { count: 1 }
    );
    assert_eq!(csv_err(b"title,url,website"), ImportError::DuplicateColumn);
    assert_eq!(
        csv_err(b"title,phrase,Recovery"),
        ImportError::DuplicateColumn
    );
    assert_eq!(csv_err(b"title,x,X "), ImportError::DuplicateColumn);

    let cols = |n: usize| {
        (0..n)
            .map(|i| format!("c{i}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    assert_eq!(csv_err(cols(65).as_bytes()), ImportError::TooManyColumns);
    assert_eq!(
        csv_err(cols(64).as_bytes()),
        ImportError::UnknownColumns { count: 64 }
    );

    let mut rows = String::from("title,notes\n");
    for _ in 0..MAX_IMPORT_ROWS {
        rows.push_str("t,n\n");
    }
    assert_eq!(
        parse(rows.as_bytes(), ImportFormat::Csv).unwrap().ready(),
        MAX_IMPORT_ROWS
    );
    rows.push_str("t,n\n");
    assert_eq!(csv_err(rows.as_bytes()), ImportError::TooManyRows);

    let mut objects = String::from("[{}");
    for _ in 0..MAX_IMPORT_ROWS {
        objects.push_str(",{}");
    }
    objects.push(']');
    assert_eq!(json_err(objects.as_bytes()), ImportError::TooManyRows);
}

#[test]
fn malformed_error_has_line_not_content() {
    let src = "title,notes\nok,\"EXAMPLE-leak never closed\nmore EXAMPLE-leak\n";
    let e = csv_err(src.as_bytes());
    assert_eq!(e, ImportError::Malformed { line: 2 });
    let shown = format!("{e} {e:?}");
    assert!(!shown.contains("EXAMPLE"), "{shown}");

    let e = json_err(b"[{\"title\": \"EXAMPLE-leak\" \"x\"}]");
    assert!(matches!(e, ImportError::Malformed { .. }));
    let shown = format!("{e} {e:?}");
    assert!(!shown.contains("EXAMPLE"), "{shown}");
}

#[test]
fn bad_rows_skipped_and_reported() {
    let src = format!(
        "{HEADER}\n{}",
        concat!(
            "Good One,u,EXAMPLE-good,,,,login,,,,\n",
            "Evil\u{202E}EXAMPLE,u,EXAMPLE-bidi,,,,login,,,,\n",
            "Wallet EXAMPLE,,,,,,crypto,EXAMPLE-chain,,EXAMPLE-memo,\n",
            "Seed EXAMPLE,,,,,,recovery,,,,\n",
            "Bogus EXAMPLE,,EXAMPLE-bogus,,,,bogus,,,,\n",
            "Extra EXAMPLE,u,EXAMPLE-extra,,,,login,,,,,EXAMPLE-extra-cell\n",
            "Note EXAMPLE,,EXAMPLE-notepw,,EXAMPLE-note body,,note,,,,\n",
            "Good Two,,,,EXAMPLE-good-note,,note,,,,\n",
            "Empty EXAMPLE,,,,,Work,,,,,\n",
        )
    );
    let batch = csv(&src);
    assert_eq!(batch.ready(), 2);
    assert_eq!(
        issues(&batch),
        vec![
            (
                2,
                RowProblem::Field(FieldError::ForbiddenChar(Field::Title))
            ),
            (3, RowProblem::MissingAddress),
            (4, RowProblem::MissingPhrase),
            (5, RowProblem::UnknownType),
            (6, RowProblem::ExtraFields),
            (7, RowProblem::UnusedField),
            (9, RowProblem::EmptyRow),
        ]
    );
    let shown = format!("{batch:?} {:?}", batch.issues());
    assert!(!shown.contains("EXAMPLE"), "{shown}");
    assert_eq!(
        format!("{batch:?}"),
        "ImportBatch { dialect: Holm, ready: 2, issues: 7, otp_ignored: 0 }"
    );
    let mut s = fresh();
    let report = s.import(batch).unwrap();
    assert_eq!(report.imported, 2);
    assert_eq!(report.skipped, 7);
    assert_eq!(titles(&s), vec!["Good One", "Good Two"]);
}

#[test]
fn unused_columns_by_type() {
    let rows = [
        // A login does not use address, memo or recovery.
        "L,u,p,,,,login,,EXAMPLE-addr,,\n",
        "L,u,p,,,,login,,,EXAMPLE-memo,\n",
        "L,u,p,,,,login,,,,EXAMPLE words\n",
        // A crypto address does not use password or recovery.
        "C,,EXAMPLE-pw,,,,crypto,,addr,,\n",
        "C,,,,,,crypto,,addr,,EXAMPLE words\n",
        // A recovery phrase does not use password, address or memo.
        "R,,EXAMPLE-pw,,,,recovery,,,,words\n",
        "R,,,,,,recovery,,addr,,words\n",
        "R,,,,,,recovery,,,memo,words\n",
        // A note does not use password, address, memo or recovery.
        "N,,,,body,,note,,addr,,\n",
        "N,,,,body,,note,,,memo,\n",
        "N,,,,body,,note,,,,words\n",
        // Username and url are for logins only, chain for crypto only.
        "N,EXAMPLE-user,,,body,,note,,,,\n",
        "N,,,https://x.example.com,body,,note,,,,\n",
        "N,,,,body,,note,EXAMPLE-chain,,,\n",
        "C,EXAMPLE-user,,,,,crypto,,addr,,\n",
        "C,,,https://x.example.com,,,crypto,,addr,,\n",
        "R,EXAMPLE-user,,,,,recovery,,,,words\n",
        "R,,,https://x.example.com,,,recovery,,,,words\n",
        "R,,,,,,recovery,EXAMPLE-chain,,,words\n",
        "L,u,p,,,,login,EXAMPLE-chain,,,\n",
        // Inferred types follow the same rule.
        ",EXAMPLE-user,,,,,,,addr,,\n",
        ",,,,,,,EXAMPLE-chain,,,words\n",
    ];
    for row in rows {
        let batch = csv(&format!("{HEADER}\n{row}"));
        assert_eq!(issues(&batch), vec![(1, RowProblem::UnusedField)], "{row}");
    }
    // Notes are used by every type.
    let batch = csv(&format!(
        "{HEADER}\nL,u,p,,n,,login,,,,\nC,,,,n,,crypto,,a,m,\nR,,,,n,,recovery,,,,w\nN,,,,n,,note,,,,\n"
    ));
    assert_eq!(batch.ready(), 4);
}

#[test]
fn type_names_and_inference() {
    let batch = csv(&format!(
        "{HEADER}\n{}",
        concat!(
            "a,,p,,,,Login,,,,\n",
            "b,,,,n,,NOTE,,,,\n",
            "c,,,,n,,secure_note,,,,\n",
            "d,,,,,,crypto_address,,x,,\n",
            "e,,,,,,CryptoCurrency,,x,,\n",
            "f,,,,,,recovery_phrase,,,,w\n",
            "g,,,,,,Seed,,,,w\n",
            "h,,,,,,,,,,w\n",
            "i,,,,,,,,x,,\n",
            "j,u,,,,,,,,,\n",
            "k,,,https://k.example.com,,,,,,,\n",
            "l,,,,n,,,,,,\n",
            "m,,,,,Work,, , ,, \n",
        )
    ));
    assert_eq!(issues(&batch), vec![(13, RowProblem::EmptyRow)]);
    let types: Vec<ItemType> = batch
        .rows
        .iter()
        .map(|r| r.input.data.item_type())
        .collect();
    use ItemType::{CryptoAddress as C, Login as L, RecoveryPhrase as R, SecureNote as N};
    assert_eq!(types, vec![L, N, N, C, C, R, R, R, C, L, L, N]);
}

#[test]
fn password_kept_byte_exact() {
    let s = imported("title,password\nP,\"  sp ace\t\"\n");
    assert_eq!(login_of(by_title(&s, "P")).1, "  sp ace\t");
    let s = imported("title,type,address,memo\nW,crypto,\" 0xab \",\" m \"\n");
    match by_title(&s, "W").data() {
        ItemData::CryptoAddress { address, memo, .. } => {
            assert_eq!(address.expose(), " 0xab ");
            assert_eq!(memo.expose(), " m ");
        }
        _ => panic!("not crypto"),
    }
}

#[test]
fn chrome_firefox_safari_detected() {
    let batch = parse(CHROME_CSV, ImportFormat::Csv).unwrap();
    assert_eq!(batch.dialect(), Dialect::Chrome);
    assert_eq!(batch.ready(), 2);
    let mut s = fresh();
    s.import(batch).unwrap();
    assert_eq!(
        login_of(by_title(&s, "Example Mail")),
        (
            "chrome.user",
            "EXAMPLE-chrome-pw",
            vec!["https://mail.example.com/login"],
            "EXAMPLE chrome note"
        )
    );
    assert_eq!(login_of(by_title(&s, "shop.example.com")).0, "shopper");

    let batch = parse(FIREFOX_CSV, ImportFormat::Csv).unwrap();
    assert_eq!(batch.dialect(), Dialect::Firefox);
    let mut s = fresh();
    s.import(batch).unwrap();
    assert_eq!(
        login_of(by_title(&s, "accounts.example.com")),
        (
            "fox.user",
            "EXAMPLE-fox-pw",
            vec!["https://user@accounts.example.com:8443/login?x"],
            ""
        )
    );
    assert_eq!(s.active_items().unwrap().count(), 1);

    let batch = parse(SAFARI_CSV, ImportFormat::Csv).unwrap();
    assert_eq!(batch.dialect(), Dialect::Safari);
    assert_eq!(batch.otp_ignored(), 1);
    assert_eq!(batch.ready(), 2);
    let mut s = fresh();
    s.import(batch).unwrap();
    assert_eq!(
        login_of(by_title(&s, "Example Bank")),
        (
            "safari.user",
            "EXAMPLE-safari-pw",
            vec!["https://bank.example.com"],
            "EXAMPLE safari note"
        )
    );
    for item in s.active_items().unwrap() {
        let (u, p, urls, n) = login_of(&item);
        for field in [item.title(), u, p, n].into_iter().chain(urls) {
            assert!(!field.contains("otpauth"));
            assert!(!field.contains("OTPSECRET"));
        }
    }
}

#[test]
fn browser_dialects_by_header_set() {
    // Chrome without the optional note column, Safari without notes, any order and case.
    assert_eq!(
        csv("URL,Name,Password,Username\nhttps://a.example.com,A,p,u\n").dialect(),
        Dialect::Chrome
    );
    assert_eq!(
        csv("otpauth,title,url,username,password\n,A,https://a.example.com,u,p\n").dialect(),
        Dialect::Safari
    );
    // Firefox needs every one of its columns.
    assert_eq!(
        csv_err(b"url,username,password,httpRealm\n"),
        ImportError::UnknownColumns { count: 1 }
    );
    // A browser column mixed into a Holm header.
    assert_eq!(
        csv_err(b"title,password,otpauth\n"),
        ImportError::UnknownColumns { count: 1 }
    );
    // A Holm header needs a title.
    assert_eq!(
        csv_err(b"username,password\n"),
        ImportError::UnknownColumns { count: 0 }
    );
}

#[test]
fn browser_title_fallbacks() {
    let s = imported(concat!(
        "name,url,username,password\n",
        ",HTTPS://WWW.Example.COM:443/path#frag,u1,p1\n",
        ",,u2,p2\n",
        ",https://[::1]:8080/x,u3,p3\n",
        ",ftp.example.com/files,u4,p4\n",
        " ,https://a@b@c.example.com?q,u5,p5\n",
    ));
    assert_eq!(login_of(by_title(&s, "www.example.com")).0, "u1");
    assert_eq!(login_of(by_title(&s, "Imported login")).0, "u2");
    assert_eq!(login_of(by_title(&s, "[::1]")).0, "u3");
    assert_eq!(login_of(by_title(&s, "ftp.example.com")).0, "u4");
    assert_eq!(login_of(by_title(&s, "c.example.com")).0, "u5");
    // A browser row with nothing in it is skipped.
    let batch = csv("name,url,username,password,note\nNamed,,,,\n,,,,\n");
    assert_eq!(
        issues(&batch),
        vec![(1, RowProblem::EmptyRow), (2, RowProblem::EmptyRow)]
    );
}

#[test]
fn json_holm_array() {
    let batch = parse(HOLM_JSON, ImportFormat::Json).unwrap();
    assert_eq!(batch.dialect(), Dialect::Holm);
    assert_eq!(batch.ready(), 4);
    let mut s = fresh();
    s.import(batch).unwrap();
    check_fixture_items(&s);
}

#[test]
fn json_keys_aliases_and_null() {
    let s = {
        let mut s = fresh();
        s.import(json(
            r#"[{" Website ":"https://j.example.com","TITLE":"J","Password":"p","username":null,"notes":null}]"#,
        ))
        .unwrap();
        s
    };
    assert_eq!(
        login_of(by_title(&s, "J")),
        ("", "p", vec!["https://j.example.com"], "")
    );
    let batch = json(r#"[{"title":"S","recovery_secret":"w1 w2"},{"title":"E"}]"#);
    assert_eq!(batch.ready(), 1);
    assert_eq!(issues(&batch), vec![(2, RowProblem::EmptyRow)]);
    assert_eq!(json("[]").ready(), 0);
}

#[test]
fn json_rejections() {
    let cases: [&[u8]; 6] = [
        br#"[{"title":"a","colour":"x"}]"#,
        br#"[{"title":"a","title":"b"}]"#,
        br#"[{"title":"a","url":"x","Website":"y"}]"#,
        br#"[{"title":1}]"#,
        br#"{"title":"a"}"#,
        br#"[{"title":"a","favourite":true}]"#,
    ];
    for c in cases {
        assert!(
            matches!(json_err(c), ImportError::Malformed { .. }),
            "{}",
            String::from_utf8_lossy(c)
        );
    }
    let deep = "[".repeat(100_000);
    assert!(matches!(
        json_err(deep.as_bytes()),
        ImportError::Malformed { .. }
    ));
    // The line of the object with the unknown key.
    assert_eq!(
        json_err(b"[\n{\"title\":\"a\"},\n\n{\"title\":\"b\",\n\"colour\":\"c\"}]"),
        ImportError::Malformed { line: 4 }
    );
    // Browser column names are not JSON keys.
    assert_eq!(
        json_err(br#"[{"name":"a"}]"#),
        ImportError::Malformed { line: 1 }
    );
}

#[test]
fn preview_counts_and_unmatched_category() {
    let src = format!(
        "{HEADER}\n{}",
        concat!(
            "One,u,p,https://one.example.com,,work,login,,,,\n",
            "Two,u,p,,,Gardening,login,,,,\n",
            "Three,,,,body,,note,,,,\n",
            "One,u,p,https://one.example.com,,Work,login,,,,\n",
            "Bad,,,,,,bogus,,,,\n",
            "Four,,,,,  ,crypto,,addr,,\n",
            "Five,,,,,,recovery,,,,w1 w2\n",
        )
    );
    let mut s = fresh();
    let before = category_names(&s);
    let batch = csv(&src);
    let preview = s.preview_import(&batch).unwrap();
    assert_eq!(
        preview,
        ImportPreview {
            dialect: Dialect::Holm,
            ready: 6,
            issues: 1,
            logins: 2,
            crypto: 1,
            phrases: 1,
            notes: 1,
            unmatched_category_rows: 1,
            duplicates: 1,
            otp_ignored: 0,
        }
    );
    assert!(!s.is_dirty());
    assert_eq!(s.active_items().unwrap().count(), 0);
    let report = s.import(batch).unwrap();
    assert_eq!(
        report,
        ImportReport {
            imported: 5,
            uncategorised: 4,
            duplicates: 1,
            skipped: 1,
        }
    );
    assert_eq!(category_names(&s), before);
    assert_eq!(before, BUILT_IN_CATEGORIES.map(str::to_owned).to_vec());
    assert_eq!(
        category_name(&s, by_title(&s, "One")).as_deref(),
        Some("Work")
    );
    assert_eq!(category_name(&s, by_title(&s, "Two")), None);
}

#[test]
fn url_parts_trimmed_then_validated() {
    let s = imported("title,url\nT,\" https://a.example.com \r\nhttps://b.example.com\n\n\"\n");
    assert_eq!(
        login_of(by_title(&s, "T")).2,
        vec!["https://a.example.com", "https://b.example.com"]
    );
    let batch = csv("title,url\nT,\"https://a.example.com\nhttps://b\u{7}.example.com\"\n");
    assert_eq!(
        issues(&batch),
        vec![(1, RowProblem::Field(FieldError::ForbiddenChar(Field::Url)))]
    );
    let many = (0..33)
        .map(|i| format!("https://{i}.example.com"))
        .collect::<Vec<_>>()
        .join("\n");
    let batch = csv(&format!("title,url\nT,\"{many}\"\n"));
    assert_eq!(
        issues(&batch),
        vec![(1, RowProblem::Field(FieldError::TooManyUrls))]
    );
}

#[test]
fn reimport_skips_duplicates() {
    let mut s = fresh();
    s.import(parse(HOLM_CSV, ImportFormat::Csv).unwrap())
        .unwrap();
    let again = parse(HOLM_CSV, ImportFormat::Csv).unwrap();
    assert_eq!(s.preview_import(&again).unwrap().duplicates, 4);
    let report = s.import(again).unwrap();
    assert_eq!(report.imported, 0);
    assert_eq!(report.duplicates, 4);
    assert_eq!(s.active_items().unwrap().count(), 4);

    let mut s = fresh();
    let report = s
        .import(csv("title,password\nTwice,p1\nTwice,p1\n"))
        .unwrap();
    assert_eq!((report.imported, report.duplicates), (1, 1));
    assert_eq!(login_of(by_title(&s, "Twice")).1, "p1");

    let mut s = fresh();
    s.import(csv(
        "title,username,url\nCaf\u{e9} Login,u,https://x.example.com\n",
    ))
    .unwrap();
    let report = s
        .import(csv(
            "title,username,url\n CAFE\u{301} Login ,U,HTTPS://X.example.com\n",
        ))
        .unwrap();
    assert_eq!((report.imported, report.duplicates), (0, 1));

    // An item in the trash still counts.
    let id = by_title(&s, "Caf\u{e9} Login").id();
    s.trash(id).unwrap();
    let report = s
        .import(csv(
            "title,username,url\nCaf\u{e9} Login,u,https://x.example.com\n",
        ))
        .unwrap();
    assert_eq!((report.imported, report.duplicates), (0, 1));

    // Same title, other type or other username: not a duplicate.
    let report = s
        .import(csv("title,username,url,notes\nCaf\u{e9} Login,v,https://x.example.com,\nCaf\u{e9} Login,,,body\n"))
        .unwrap();
    assert_eq!((report.imported, report.duplicates), (2, 0));
}

/// Imports `src` into `s` and returns (imported, duplicates).
fn import_counts(s: &mut S, src: &str) -> (usize, usize) {
    let report = s.import(csv(src)).unwrap();
    (report.imported, report.duplicates)
}

#[test]
fn dedup_only_skips_identical_items() {
    // Same title and type, different secret: both are kept.
    let mut s = fresh();
    let phrases = format!(
        "{HEADER}\nLedger,,,,,,recovery,,,,alpha beta\nLedger,,,,,,recovery,,,,gamma delta\n"
    );
    assert_eq!(import_counts(&mut s, &phrases), (2, 0));
    let notes = format!(
        "{HEADER}\nWi-Fi,,,,EXAMPLE body one,,note,,,,\nWi-Fi,,,,EXAMPLE body two,,note,,,,\n"
    );
    assert_eq!(import_counts(&mut s, &notes), (2, 0));
    let wallet = format!("{HEADER}\nWallet,,,,,,crypto,EXAMPLE-chain,EXAMPLE-addr-1,,\n");
    assert_eq!(import_counts(&mut s, &wallet), (1, 0));
    let other_address = format!("{HEADER}\nWallet,,,,,,crypto,EXAMPLE-chain,EXAMPLE-addr-2,,\n");
    assert_eq!(import_counts(&mut s, &other_address), (1, 0));
    assert_eq!(s.active_items().unwrap().count(), 6);

    // The same files again: every item is identical to one in the vault.
    for src in [&phrases, &notes, &wallet, &other_address] {
        let (imported, duplicates) = import_counts(&mut s, src);
        assert_eq!(imported, 0, "{src}");
        assert!(duplicates > 0, "{src}");
    }
    assert_eq!(s.active_items().unwrap().count(), 6);

    // One field differs: not a duplicate. One row per field.
    let mut s = fresh();
    let base = "Same,u,p,https://x.example.com,n,,login,,,,\n";
    assert_eq!(import_counts(&mut s, &format!("{HEADER}\n{base}")), (1, 0));
    let changed = [
        "Same,u,p,https://x.example.com,n,Work,login,,,,\n",
        "Same,v,p,https://x.example.com,n,,login,,,,\n",
        "Same,u,P,https://x.example.com,n,,login,,,,\n",
        "Same,u,p,https://y.example.com,n,,login,,,,\n",
        "Same,u,p,https://x.example.com,N,,login,,,,\n",
        "Same,u,p,https://x.example.com,n ,,login,,,,\n",
        "Other,u,p,https://x.example.com,n,,login,,,,\n",
    ];
    for row in changed {
        assert_eq!(
            import_counts(&mut s, &format!("{HEADER}\n{row}")),
            (1, 0),
            "{row}"
        );
    }
    let crypto = "C,,,,n,,crypto,ch,addr,memo,\n";
    assert_eq!(
        import_counts(&mut s, &format!("{HEADER}\n{crypto}")),
        (1, 0)
    );
    for row in [
        "C,,,,n,,crypto,CH2,addr,memo,\n",
        "C,,,,n,,crypto,ch,addr,memo2,\n",
        "C,,,,n2,,crypto,ch,addr,memo,\n",
    ] {
        assert_eq!(
            import_counts(&mut s, &format!("{HEADER}\n{row}")),
            (1, 0),
            "{row}"
        );
    }
    let phrase = "R,,,,n,,recovery,,,,w1 w2\n";
    assert_eq!(
        import_counts(&mut s, &format!("{HEADER}\n{phrase}")),
        (1, 0)
    );
    assert_eq!(
        import_counts(&mut s, &format!("{HEADER}\nR,,,,n2,,recovery,,,,w1 w2\n")),
        (1, 0)
    );

    // Display fields compare folded; the phrase compares by its words.
    let before = s.active_items().unwrap().count();
    for row in [
        " SAME ,U,p,HTTPS://X.example.com,n,,login,,,,\n",
        "c,,,,n,,crypto,CH,addr,memo,\n",
        "R,,,,n,,recovery,,,,\"  w1\n w2 \"\n",
    ] {
        assert_eq!(
            import_counts(&mut s, &format!("{HEADER}\n{row}")),
            (0, 1),
            "{row}"
        );
    }
    assert_eq!(s.active_items().unwrap().count(), before);

    // Rows in one file are compared with each other the same way.
    let mut s = fresh();
    let twice = format!("{HEADER}\nLedger,,,,,,recovery,,,,a b\nLedger,,,,,,recovery,,,,a b\n");
    assert_eq!(import_counts(&mut s, &twice), (1, 1));
}

#[test]
fn dedup_key_layout() {
    assert_eq!(
        dedup_key(
            ItemType::Login,
            " Caf\u{e9} ",
            "U",
            &["https://A.example.com", "b"],
            ""
        )
        .as_str(),
        "caf\u{e9}\0u\0https://a.example.com\nb\0\0login"
    );
    assert_eq!(
        dedup_key(ItemType::CryptoAddress, "W", "", &[], "Main Net").as_str(),
        "w\0\0\0main net\0crypto"
    );
    assert_eq!(
        dedup_key(ItemType::SecureNote, "N", "", &[], "").as_str(),
        "n\0\0\0\0note"
    );
}

#[test]
fn metadata_columns_read() {
    let s = imported(concat!(
        "title,password,favourite,created,updated\n",
        "M,p,true,1700000000,1700000100\n",
        "U,p,FALSE,,\n",
        "C,p,,1600000000,\n",
        "F,p,,1800000000,\n",
        "D,p,,,1600000000\n",
    ));
    let m = by_title(&s, "M");
    assert!(m.favourite());
    assert_eq!((m.created(), m.updated()), (Timestamp(NOW), Timestamp(NOW)));
    let u = by_title(&s, "U");
    assert!(!u.favourite());
    assert_eq!((u.created(), u.updated()), (Timestamp(NOW), Timestamp(NOW)));
    let c = by_title(&s, "C");
    assert_eq!(
        (c.created(), c.updated()),
        (Timestamp(1_600_000_000), Timestamp(NOW))
    );
    let f = by_title(&s, "F");
    assert_eq!((f.created(), f.updated()), (Timestamp(NOW), Timestamp(NOW)));
    let d = by_title(&s, "D");
    assert_eq!(
        (d.created(), d.updated()),
        (Timestamp(1_600_000_000), Timestamp(1_600_000_000))
    );

    let batch = csv(concat!(
        "title,password,favourite,created,updated\n",
        "a,p,yes,,\n",
        "b,p,,x,\n",
        "c,p,,200,100\n",
        "d,p,,+5,\n",
        "e,p,,,1.5\n",
        "f,p,,99999999999999999999,\n",
        "g,p,,-5,-5\n",
    ));
    assert_eq!(
        issues(&batch),
        vec![
            (1, RowProblem::BadFavourite),
            (2, RowProblem::BadTimestamp),
            (3, RowProblem::BadTimestamp),
            (4, RowProblem::BadTimestamp),
            (5, RowProblem::BadTimestamp),
            (6, RowProblem::BadTimestamp),
        ]
    );
    assert_eq!(batch.ready(), 1);

    let s = imported("title,password\nNo Meta,p\n");
    let n = by_title(&s, "No Meta");
    assert!(!n.favourite());
    assert_eq!((n.created(), n.updated()), (Timestamp(NOW), Timestamp(NOW)));
}

#[test]
fn recovery_never_from_password() {
    let batch = csv("title,password,notes,type\nR,EXAMPLE-pw,EXAMPLE-n,recovery\n");
    assert_eq!(issues(&batch), vec![(1, RowProblem::MissingPhrase)]);
    assert_eq!(batch.ready(), 0);
    let batch = csv("title,address,type\nC,  ,crypto\n");
    assert_eq!(issues(&batch), vec![(1, RowProblem::MissingAddress)]);
    // A blank chain stays blank.
    let s = imported("title,type,address\nW,crypto,addr\n");
    match by_title(&s, "W").data() {
        ItemData::CryptoAddress { chain, .. } => assert_eq!(chain.as_str(), ""),
        _ => panic!("not crypto"),
    }
}

fn seed_note(title: &str) -> Item {
    Item {
        fields: Vec::new(),
        id: ItemId::random().unwrap(),
        title: Text::new(title.to_owned()),
        category: None,
        favourite: false,
        created: Timestamp(1),
        updated: Timestamp(1),
        trashed: None,
        data: ItemData::SecureNote {
            body: SecretText::new("b".to_owned()),
        },
    }
}

#[test]
fn import_is_atomic_on_item_limit() {
    let mut s = fresh();
    for i in 0..MAX_ITEMS - 1 {
        s.seed(seed_note(&format!("n{i}")));
    }
    let before = s.store().bytes.clone();
    // Two new rows do not fit.
    assert_eq!(
        s.import(csv("title,notes\nx,b\ny,b\n")),
        Err(CoreError::TooManyItems)
    );
    assert_eq!(s.stored_count(), MAX_ITEMS - 1);
    assert!(!s.is_dirty());
    assert_eq!(s.store().bytes, before);
    // Duplicates are dropped first, so they never count against the limit.
    let preview = s.preview_import(&csv("title,notes\nn0,b\nn1,b\n")).unwrap();
    assert_eq!(preview.duplicates, 2);
}

#[test]
fn import_rolls_back_when_too_large_to_save() {
    let mut s = fresh();
    let big = "a".repeat(65_536);
    let big_note = |title: &str| {
        let mut item = seed_note(title);
        item.data = ItemData::SecureNote {
            body: SecretText::new(big.clone()),
        };
        item
    };
    s.seed_to_the_brim(|i| big_note(&format!("big {i}")));
    // Saved once, so the file holds every seeded item.
    s.save().unwrap();
    let count = s.stored_count();
    let before = s.store().bytes.clone();
    let rows = format!("title,notes\nnew one,{big}\nnew two,{big}\n");
    assert_eq!(
        s.import(csv(&rows)),
        Err(CoreError::Vault(VaultError::TooLargeToSave))
    );
    assert_eq!(s.stored_count(), count);
    assert!(!s.is_dirty());
    assert_eq!(s.store().bytes, before);
}

#[test]
fn import_then_reopen_persists() {
    let mut s = fresh();
    s.import(parse(HOLM_CSV, ImportFormat::Csv).unwrap())
        .unwrap();
    assert!(!s.lock().discarded_unsaved);
    s.unlock(&MasterPassword::new(PW.to_owned())).unwrap();
    check_fixture_items(&s);
    let id = by_title(&s, "Example Recovery").id();
    assert_eq!(
        s.reveal_phrase(id, &MasterPassword::new(PW.to_owned()))
            .unwrap()
            .expose(),
        PHRASE
    );
}

#[test]
fn locked_session_refuses() {
    let mut s = fresh();
    s.lock();
    let batch = parse(HOLM_CSV, ImportFormat::Csv).unwrap();
    assert_eq!(s.preview_import(&batch), Err(CoreError::Locked));
    assert_eq!(s.import(batch), Err(CoreError::Locked));
}

#[test]
fn error_messages_are_fixed_text() {
    for e in [
        ImportError::TooLarge,
        ImportError::NotUtf8,
        ImportError::Empty,
        ImportError::UnknownColumns { count: 3 },
        ImportError::DuplicateColumn,
        ImportError::TooManyColumns,
        ImportError::TooManyRows,
        ImportError::Malformed { line: 7 },
    ] {
        assert!(!e.to_string().is_empty());
    }
    assert_eq!(
        ImportError::Malformed { line: 7 }.to_string(),
        "the file is not valid at line 7"
    );
}

#[test]
fn old_csv_has_no_fields() {
    let s = imported(concat!(
        "title,username,password,url,notes,category,type,",
        "chain,address,memo,recovery,favourite,created,updated\n",
        "Old,user,EXAMPLE-pw,https://example.com,,,login,,,,,false,1700000000,1700000000\n",
    ));
    let item = by_title(&s, "Old");
    assert!(item.fields().is_empty());
    assert_eq!(login_of(item).1, "EXAMPLE-pw");
}

#[test]
fn field_gap_is_a_row_error() {
    let batch = csv("title,password,field2_label\nT,pw,Pin\n");
    assert_eq!(issues(&batch), vec![(1, RowProblem::FieldGap)]);
    assert_eq!(batch.ready(), 0);
    let mut s = fresh();
    let report = s.import(batch).unwrap();
    assert_eq!(report.imported, 0);
    assert_eq!(report.skipped, 1);
    assert_eq!(s.active_items().unwrap().count(), 0);
}

#[test]
fn bad_kind_is_a_row_error() {
    let batch = csv(concat!(
        "title,password,field1_label,field1_kind,field1_value\n",
        "T,pw,Pin,password,EXAMPLE-field-secret\n",
    ));
    assert_eq!(issues(&batch), vec![(1, RowProblem::BadFieldKind)]);
    assert_eq!(batch.ready(), 0);
}

#[test]
fn bad_expiry_is_a_row_error() {
    let batch = csv(concat!(
        "title,password,field1_label,field1_kind,field1_value,field1_expiry\n",
        "A,pw,Note,text,public,2026-13-01\n",
        "B,pw,Note,text,public,2026-11-05T00:00:00Z\n",
        "C,pw,When,date,,\n",
        "D,pw,Note,text,public,   \n",
    ));
    assert_eq!(
        issues(&batch),
        vec![
            (1, RowProblem::BadDate),
            (2, RowProblem::BadDate),
            (3, RowProblem::BadDate),
        ]
    );
    assert_eq!(batch.ready(), 1);
    let mut s = fresh();
    s.import(batch).unwrap();
    assert_eq!(by_title(&s, "D").fields()[0].expiry(), None);
}

#[test]
fn empty_secret_slot_imports() {
    let s = imported("title,password,field1_label,field1_kind,field1_value\nT,pw,Pin,SeCrEt,\n");
    let field = &by_title(&s, "T").fields()[0];
    assert_eq!(field.label(), "Pin");
    assert_eq!(field.kind(), FieldKind::Secret);
    assert_eq!(field.expiry(), None);
    match field.value() {
        FieldValue::Secret(value) => assert_eq!(value.expose(), ""),
        _ => panic!("secret"),
    }
}

#[test]
fn ten_fields_import() {
    let mut header = String::from("title,password");
    let mut row = String::from("Ten,pw");
    for n in 1..=10 {
        header.push_str(&format!(
            ",field{n}_label,field{n}_kind,field{n}_value,field{n}_expiry"
        ));
        if n == 1 {
            row.push_str(",L1,Text,v1,");
        } else if n == 2 {
            row.push_str(",When,DATE,2026-11-05,2026-12-01");
        } else {
            row.push_str(&format!(",L{n},text,v{n},"));
        }
    }
    let s = imported(&format!("{header}\n{row}\n"));
    let item = by_title(&s, "Ten");
    assert_eq!(item.fields().len(), 10);
    assert_eq!(item.fields()[0].kind(), FieldKind::Text);
    assert_eq!(item.fields()[1].kind(), FieldKind::Date);
    match item.fields()[1].value() {
        FieldValue::Date(date) => assert_eq!(format_date(*date), *b"2026-11-05"),
        _ => panic!("date"),
    }
    assert_eq!(
        item.fields()[1].expiry().map(format_date),
        Some(*b"2026-12-01")
    );
    assert_eq!(item.fields()[9].label(), "L10");
    assert_eq!(
        csv_err(b"title,field1_label,field1_label"),
        ImportError::DuplicateColumn
    );
}

#[test]
fn browser_fixtures_unchanged() {
    let chrome = parse(CHROME_CSV, ImportFormat::Csv).unwrap();
    assert_eq!(chrome.dialect(), Dialect::Chrome);
    assert_eq!(chrome.ready(), 2);
    let firefox = parse(FIREFOX_CSV, ImportFormat::Csv).unwrap();
    assert_eq!(firefox.dialect(), Dialect::Firefox);
    assert_eq!(firefox.ready(), 1);
    let safari = parse(SAFARI_CSV, ImportFormat::Csv).unwrap();
    assert_eq!(safari.dialect(), Dialect::Safari);
    assert_eq!(safari.ready(), 2);
    assert_eq!(safari.otp_ignored(), 1);

    let mut s = fresh();
    s.import(chrome).unwrap();
    s.import(firefox).unwrap();
    s.import(safari).unwrap();
    assert_eq!(s.active_items().unwrap().count(), 5);
    assert!(
        s.active_items()
            .unwrap()
            .all(|item| item.fields().is_empty())
    );
}

#[test]
fn same_item_sees_custom_fields() {
    let different = concat!(
        "title,password,field1_label,field1_kind,field1_value\n",
        "Twin,pw,Pin,secret,EXAMPLE-a\n",
        "Twin,pw,Pin,secret,EXAMPLE-b\n",
    );
    let mut s = fresh();
    let report = s.import(csv(different)).unwrap();
    assert_eq!(report.imported, 2);
    assert_eq!(report.duplicates, 0);

    let identical = concat!(
        "title,password,field1_label,field1_kind,field1_value\n",
        "Twin,pw,Pin,secret,EXAMPLE-a\n",
        "Twin,pw,Pin,secret,EXAMPLE-a\n",
    );
    let report = fresh().import(csv(identical)).unwrap();
    assert_eq!(report.imported, 1);
    assert_eq!(report.duplicates, 1);

    let other = concat!(
        "title,password,field1_label,field1_kind,field1_value\n",
        "Twin,pw,Pin,secret,EXAMPLE-c\n",
    );
    assert_eq!(s.preview_import(&csv(other)).unwrap().duplicates, 0);
    let same = concat!(
        "title,password,field1_label,field1_kind,field1_value\n",
        "Twin,pw,Pin,secret,EXAMPLE-a\n",
    );
    assert_eq!(s.preview_import(&csv(same)).unwrap().duplicates, 1);
}

#[test]
fn export_debug_has_no_secret() {
    let err = csv_err(b"title,password,nope\nT,EXAMPLE-field-secret,x\n");
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains("EXAMPLE"));

    let err = json_err(br#"[{"title":"T","password":"EXAMPLE-field-secret","nested":{"a":"x"}}]"#);
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains("EXAMPLE"));

    let batch = csv(concat!(
        "title,password,field1_label,field1_kind,field1_value\n",
        "T,pw,Pin,password,EXAMPLE-field-secret\n",
    ));
    let shown = format!("{batch:?} {:?}", batch.issues());
    assert!(!shown.contains("EXAMPLE"));
    assert_eq!(issues(&batch), vec![(1, RowProblem::BadFieldKind)]);
}
