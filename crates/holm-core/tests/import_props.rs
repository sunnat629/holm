//! Property tests for plaintext import.
//!
//! `errors_never_contain_input`: whatever the bytes, `parse` returns, and nothing it
//! returns (error, batch `Debug`, row issues) repeats the planted text.
//! `generated_rows_parse_to_same_fields`: valid rows of all four types, written as
//! RFC 4180 CSV with every cell quoted, come back field for field and byte for byte
//! after `parse` and `import`, with timestamps clamped to the test clock.
//!
//! The crate's own `push_quoted` is crate-private, so `quote` below writes the same
//! RFC 4180 form (wrap in `"`, double every `"`). `MemStore` and `FakeClock` are
//! test-only and crate-private too, so this file has its own in-memory store and uses
//! a fixed clock.

use std::cell::RefCell;

use holm_core::clock::Clock;
use holm_core::import::{ImportFormat, MAX_IMPORT_ROWS, parse};
use holm_core::item::{Item, ItemData, Timestamp};
use holm_core::session::Session;
use holm_core::store::{StoreError, VaultStore};
use holm_crypto::MasterPassword;
use holm_crypto::kdf::KdfParams;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";
const PLANT: &str = "EXAMPLE-leak";
const NOW: i64 = 1_700_000_000;

struct ImportClock;

impl Clock for ImportClock {
    fn now_unix(&self) -> Timestamp {
        Timestamp(NOW)
    }

    fn monotonic(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
}

/// A vault file held in memory.
#[derive(Default)]
struct Mem(Option<Vec<u8>>);

impl VaultStore for Mem {
    fn read(&mut self) -> Result<Vec<u8>, StoreError> {
        self.0.clone().ok_or(StoreError::NotFound)
    }
    fn replace(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        self.0 = Some(bytes.to_vec());
        Ok(())
    }
    fn create_new(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        if self.0.is_some() {
            return Err(StoreError::AlreadyExists);
        }
        self.0 = Some(bytes.to_vec());
        Ok(())
    }
    fn remove_stale_temps(&mut self) -> Result<usize, StoreError> {
        Ok(0)
    }
}

// ---------------------------------------------------------------- no echo

/// Checks one input in both formats.
fn check_no_echo(bytes: &[u8]) -> Result<(), TestCaseError> {
    for format in [ImportFormat::Csv, ImportFormat::Json] {
        match parse(bytes, format) {
            Err(e) => {
                let shown = format!("{e} {e:?}");
                prop_assert!(!shown.contains("EXAMPLE"), "{}", shown);
            }
            Ok(batch) => {
                prop_assert!(batch.ready() + batch.issues().len() <= MAX_IMPORT_ROWS);
                let shown = format!("{batch:?}");
                prop_assert!(!shown.contains("EXAMPLE"), "{}", shown);
                for issue in batch.issues() {
                    let shown = format!("{issue:?}");
                    prop_assert!(!shown.contains("EXAMPLE"), "{}", shown);
                }
            }
        }
    }
    Ok(())
}

/// Random bytes with the plant inserted somewhere.
fn planted_bytes() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::collection::vec(any::<u8>(), 0..256),
        any::<prop::sample::Index>(),
    )
        .prop_map(|(mut bytes, at)| {
            let at = at.index(bytes.len() + 1);
            bytes.splice(at..at, PLANT.bytes());
            bytes
        })
}

const HEADERS: [&str; 6] = [
    "title,username,password,url,notes,category,type,chain,address,memo,recovery",
    "title,password,favourite,created,updated",
    "name,url,username,password,note",
    "Title,URL,Username,Password,Notes,OTPAuth",
    "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged",
    "title,EXAMPLE-leak",
];

const CELLS: [&str; 20] = [
    "",
    " ",
    "EXAMPLE-leak",
    "\"EXAMPLE-leak\"",
    "\"EXAMPLE-leak",
    "EXAMPLE-leak\"x",
    "\"EXAMPLE\r\nleak\"",
    "\u{202e}EXAMPLE-leak",
    "EXAMPLE-leak\u{7}",
    "login",
    "crypto",
    "recovery",
    "note",
    "bogus",
    "true",
    "yes",
    "1700000000",
    "-x",
    "https://EXAMPLE-leak.example.com",
    "Work",
];

/// A CSV file built from a known header and cells that hold the plant.
fn planted_csv() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::sample::select(&HEADERS[..]),
        prop::collection::vec(
            prop::collection::vec(prop::sample::select(&CELLS[..]), 0..14),
            0..6,
        ),
    )
        .prop_map(|(header, rows)| {
            let mut out = format!("{header}\n");
            for row in rows {
                out.push_str(&row.join(","));
                out.push_str("\r\n");
            }
            out.into_bytes()
        })
}

const KEYS: [&str; 8] = [
    "title",
    "password",
    "url",
    "website",
    "type",
    "recovery",
    "colour",
    "EXAMPLE-leak",
];

fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A JSON array of flat objects built from known keys and values that hold the plant.
fn planted_json() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop::collection::vec(
            (
                prop::sample::select(&KEYS[..]),
                prop::option::of(prop::sample::select(&CELLS[..])),
            ),
            0..6,
        ),
        0..5,
    )
    .prop_map(|objects| {
        let objects: Vec<String> = objects
            .iter()
            .map(|fields| {
                let fields: Vec<String> = fields
                    .iter()
                    .map(|(k, v)| {
                        let v = v.map_or_else(|| "null".to_owned(), json_string);
                        format!("{}:{v}", json_string(k))
                    })
                    .collect();
                format!("{{{}}}", fields.join(","))
            })
            .collect();
        format!("[{}]", objects.join(",\n")).into_bytes()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn errors_never_contain_input(
        bytes in prop_oneof![planted_bytes(), planted_csv(), planted_json()],
    ) {
        check_no_echo(&bytes)?;
    }
}

// ---------------------------------------------------------------- round trip

#[derive(Clone, Debug)]
enum Kind {
    Login {
        username: String,
        password: String,
        urls: Vec<String>,
        notes: String,
    },
    Crypto {
        chain: String,
        address: String,
        memo: String,
        notes: String,
    },
    Recovery {
        phrase: String,
        notes: String,
    },
    Note {
        body: String,
    },
}

#[derive(Clone, Debug)]
struct Row {
    title: String,
    category: Option<&'static str>,
    favourite: bool,
    created: i64,
    updated: i64,
    kind: Kind,
}

/// One-line display text: printable ASCII (with `"` and `,`) and some non-ASCII,
/// including a combining mark. No controls, no bidi.
fn display(max: usize) -> impl Strategy<Value = String> {
    prop::string::string_regex(&format!("[ -~\u{e9}\u{301}\u{fc}\u{20ac}]{{0,{max}}}")).unwrap()
}

/// A one-line secret: may start or end with spaces or tabs.
fn line_secret(max: usize) -> impl Strategy<Value = String> {
    prop::string::string_regex(&format!("[ -~\t\u{e9}\u{301}]{{0,{max}}}")).unwrap()
}

/// Multi-line text with CR, LF and CRLF.
fn multi_line(max: usize) -> impl Strategy<Value = String> {
    prop::string::string_regex(&format!("[ -~\t\r\n\u{e9}]{{0,{max}}}")).unwrap()
}

fn kind() -> impl Strategy<Value = Kind> {
    let url = "https://[a-z]{1,8}\\.example\\.com(/[a-z0-9]{0,6})?";
    prop_oneof![
        (
            display(16),
            line_secret(24),
            prop::collection::vec(url, 0..3),
            multi_line(40)
        )
            .prop_map(|(username, password, urls, notes)| Kind::Login {
                username,
                password,
                urls,
                notes,
            }),
        (
            display(12),
            "[!-~][ -~\t]{0,20}",
            line_secret(16),
            multi_line(40)
        )
            .prop_map(|(chain, address, memo, notes)| Kind::Crypto {
                chain,
                address,
                memo,
                notes,
            }),
        ("[a-z]{3,8}( [a-z]{3,8}){2,11}", multi_line(40))
            .prop_map(|(phrase, notes)| Kind::Recovery { phrase, notes }),
        multi_line(60).prop_map(|body| Kind::Note { body }),
    ]
}

fn row() -> impl Strategy<Value = Row> {
    (
        display(16),
        prop_oneof![
            Just(None),
            Just(Some("Personal")),
            Just(Some("Work")),
            Just(Some("Community")),
        ],
        any::<bool>(),
        -1_000_000i64..2_000_000_000,
        0i64..1_000_000,
        kind(),
    )
        .prop_map(|(title, category, favourite, created, later, kind)| Row {
            title,
            category,
            favourite,
            created,
            updated: created + later,
            kind,
        })
}

/// RFC 4180: wrap in quotes and double every quote (the form `push_quoted` writes).
fn quote(out: &mut String, cell: &str) {
    out.push('"');
    out.push_str(&cell.replace('"', "\"\""));
    out.push('"');
}

const EXPORT_HEADER: [&str; 14] = [
    "title",
    "username",
    "password",
    "url",
    "notes",
    "category",
    "type",
    "chain",
    "address",
    "memo",
    "recovery",
    "favourite",
    "created",
    "updated",
];

/// The rows as a CSV file, every cell quoted, `\r\n` after each row. Titles get a
/// unique prefix so they can be found again and are never duplicates.
fn write_csv(case: usize, rows: &[Row]) -> String {
    let mut out = String::new();
    let mut line = |cells: &[&str]| {
        for (i, c) in cells.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            quote(&mut out, c);
        }
        out.push_str("\r\n");
    };
    line(&EXPORT_HEADER);
    for (i, r) in rows.iter().enumerate() {
        let title = format!("r{case}.{i}|{}", r.title);
        let (created, updated) = (r.created.to_string(), r.updated.to_string());
        let favourite = if r.favourite { "true" } else { "false" };
        let category = r.category.unwrap_or("");
        let cells: [&str; 14] = match &r.kind {
            Kind::Login {
                username,
                password,
                urls,
                notes,
            } => {
                let urls = urls.join("\n");
                line(&[
                    &title, username, password, &urls, notes, category, "login", "", "", "", "",
                    favourite, &created, &updated,
                ]);
                continue;
            }
            Kind::Crypto {
                chain,
                address,
                memo,
                notes,
            } => [
                &title, "", "", "", notes, category, "crypto", chain, address, memo, "", favourite,
                &created, &updated,
            ],
            Kind::Recovery { phrase, notes } => [
                &title, "", "", "", notes, category, "recovery", "", "", "", phrase, favourite,
                &created, &updated,
            ],
            Kind::Note { body } => [
                &title, "", "", "", body, category, "note", "", "", "", "", favourite, &created,
                &updated,
            ],
        };
        line(&cells);
    }
    out
}

/// Compares one stored item with the row it came from.
fn check_item(s: &mut Session<Mem>, item_title: &str, r: &Row) -> Result<(), TestCaseError> {
    let item: &Item = s
        .active_items()
        .unwrap()
        .find(|i| i.title() == item_title)
        .expect("imported item");
    let id = item.id();
    prop_assert_eq!(item.favourite(), r.favourite);
    prop_assert_eq!(item.created(), Timestamp(r.created.clamp(0, NOW)));
    prop_assert_eq!(item.updated(), Timestamp(r.updated.clamp(0, NOW)));
    let category = item.category().and_then(|c| {
        s.categories()
            .unwrap()
            .iter()
            .find(|k| k.id() == c)
            .map(|k| k.name().to_owned())
    });
    prop_assert_eq!(category.as_deref(), r.category);
    match (item.data(), &r.kind) {
        (
            ItemData::Login {
                username,
                password,
                urls,
                notes,
            },
            Kind::Login {
                username: u,
                password: p,
                urls: us,
                notes: n,
            },
        ) => {
            prop_assert_eq!(username.as_str(), u.as_str());
            prop_assert_eq!(password.expose(), p.as_str());
            let urls: Vec<&str> = urls.iter().map(|x| x.as_str()).collect();
            prop_assert_eq!(urls, us.iter().map(String::as_str).collect::<Vec<_>>());
            prop_assert_eq!(notes.expose(), n.as_str());
        }
        (
            ItemData::CryptoAddress {
                chain,
                address,
                memo,
                notes,
            },
            Kind::Crypto {
                chain: c,
                address: a,
                memo: m,
                notes: n,
            },
        ) => {
            prop_assert_eq!(chain.as_str(), c.as_str());
            prop_assert_eq!(address.expose(), a.as_str());
            prop_assert_eq!(memo.expose(), m.as_str());
            prop_assert_eq!(notes.expose(), n.as_str());
        }
        (ItemData::RecoveryPhrase { notes, .. }, Kind::Recovery { phrase, notes: n }) => {
            prop_assert_eq!(notes.expose(), n.as_str());
            let shown = s
                .reveal_phrase(id, &MasterPassword::new(PW.to_owned()))
                .unwrap();
            prop_assert_eq!(shown, phrase.as_str());
        }
        (ItemData::SecureNote { body }, Kind::Note { body: b }) => {
            prop_assert_eq!(body.expose(), b.as_str());
        }
        _ => prop_assert!(false, "wrong item type for {}", item_title),
    }
    Ok(())
}

#[test]
fn generated_rows_parse_to_same_fields() {
    let mut s = Session::new(Mem::default(), Box::new(ImportClock));
    s.create(&MasterPassword::new(PW.to_owned()), &KdfParams::FLOOR)
        .unwrap();
    let session = RefCell::new(s);
    let case = RefCell::new(0usize);
    let mut runner = TestRunner::new(Config {
        cases: 24,
        failure_persistence: None,
        ..Config::default()
    });
    runner
        .run(&prop::collection::vec(row(), 1..7), |rows| {
            let n = {
                let mut c = case.borrow_mut();
                *c += 1;
                *c
            };
            let src = write_csv(n, &rows);
            let batch = parse(src.as_bytes(), ImportFormat::Csv).unwrap();
            prop_assert!(batch.issues().is_empty(), "{:?}", batch.issues());
            prop_assert_eq!(batch.ready(), rows.len());
            let mut s = session.borrow_mut();
            let report = s.import(batch).unwrap();
            prop_assert_eq!(report.imported, rows.len());
            prop_assert_eq!(report.duplicates, 0);
            for (i, r) in rows.iter().enumerate() {
                check_item(&mut s, &format!("r{n}.{i}|{}", r.title), r)?;
            }
            Ok(())
        })
        .unwrap();
}
