//! Property tests for custom fields through plaintext export and import.
//!
//! `csv_round_trip_keeps_custom_fields` and `json_round_trip_keeps_custom_fields`:
//! items with 0 to 10 custom fields of all four kinds (labels and values with quotes,
//! commas, newlines, non-ASCII and a leading `=`, `+`, `-` or `@`, optional expiry)
//! are seeded into vault A, exported, and imported into vault B. Every label, kind,
//! value byte and expiry must come back, a re-export of B must be byte-identical to
//! the export of A, and importing A's export back into A must add nothing.
//! `changed_custom_secret_is_not_a_duplicate`: the same row again is a duplicate, and
//! the row with one byte of one custom secret changed is not.
//!
//! Items are seeded by importing a CSV written here, so only the public API is used.
//! The generated values are fake, but the model types still print kinds and lengths
//! only, and every comparison uses a fixed failure message, so no value is printed.

use std::cell::{Cell, RefCell};
use std::fmt;

use holm_core::clock::Clock;
use holm_core::fields::{CustomField, FieldKind, FieldValue, format_date};
use holm_core::import::{ImportFormat, parse};
use holm_core::item::{ItemData, Timestamp};
use holm_core::session::Session;
use holm_core::store::{StoreError, VaultStore};
use holm_crypto::kdf::KdfParams;
use holm_crypto::{MasterPassword, SecretBuf};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";
const NOW: i64 = 1_700_000_000;
const SLOTS: usize = 10;

struct FixedClock;

impl Clock for FixedClock {
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

fn password() -> MasterPassword {
    MasterPassword::new(PW.to_owned())
}

/// A new unlocked vault on the fixed clock.
fn new_session() -> Session<Mem> {
    let mut s = Session::new(Mem::default(), Box::new(FixedClock));
    s.create(&password(), &KdfParams::FLOOR).unwrap();
    s
}

fn runner() -> TestRunner {
    TestRunner::new(Config {
        cases: 64,
        failure_persistence: None,
        ..Config::default()
    })
}

// ---------------------------------------------------------------- model

#[derive(Clone)]
enum Value {
    Text(String),
    Secret(String),
    Multiline(String),
    /// `YYYY-MM-DD`.
    Date(String),
}

impl Value {
    fn kind(&self) -> FieldKind {
        match self {
            Value::Text(_) => FieldKind::Text,
            Value::Secret(_) => FieldKind::Secret,
            Value::Multiline(_) => FieldKind::MultilineSecret,
            Value::Date(_) => FieldKind::Date,
        }
    }

    fn kind_cell(&self) -> &'static str {
        match self {
            Value::Text(_) => "text",
            Value::Secret(_) => "secret",
            Value::Multiline(_) => "multiline",
            Value::Date(_) => "date",
        }
    }

    fn cell(&self) -> &str {
        match self {
            Value::Text(s) | Value::Secret(s) | Value::Multiline(s) | Value::Date(s) => s,
        }
    }
}

#[derive(Clone)]
struct Field {
    label: String,
    value: Value,
    /// `YYYY-MM-DD`.
    expiry: Option<String>,
}

/// Kind and lengths only, never a value.
impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Value").field("kind", &self.kind()).finish()
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("kind", &self.value.kind())
            .field("label_len", &self.label.len())
            .field("value_len", &self.value.cell().len())
            .field("expiry", &self.expiry.is_some())
            .finish()
    }
}

/// One login: its password and its custom fields.
#[derive(Clone)]
struct Entry {
    password: String,
    fields: Vec<Field>,
}

/// Lengths and field shapes only, never a value.
impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("password_len", &self.password.len())
            .field("fields", &self.fields)
            .finish()
    }
}

// ---------------------------------------------------------------- strategies

/// Starts that matter to spreadsheets and to CSV quoting.
const PREFIXES: [&str; 9] = ["", "=", "+", "-", "@", "\"", ",", "=SUM(A1)", "\"\","];
/// The same, without the empty one, so a label is never blank.
const LABEL_PREFIXES: [&str; 9] = ["=", "+", "-", "@", "\"", ",", "=HYPERLINK(", "L", "\u{e9}"];

/// One display line: printable ASCII (with `"` and `,`) and some non-ASCII,
/// including a combining mark. No leading or trailing whitespace.
fn label() -> impl Strategy<Value = String> {
    (
        prop::sample::select(&LABEL_PREFIXES[..]),
        "[ -~\u{e9}\u{301}\u{fc}\u{20ac}]{0,16}",
    )
        .prop_map(|(prefix, body)| format!("{prefix}{body}").trim_end().to_owned())
}

/// A prefix from [`PREFIXES`] and a body, trimmed at both ends.
fn prefixed(body: &'static str) -> impl Strategy<Value = String> {
    (prop::sample::select(&PREFIXES[..]), body)
        .prop_map(|(prefix, body)| format!("{prefix}{body}").trim().to_owned())
}

fn date() -> impl Strategy<Value = String> {
    (1u16..=9999, 1u8..=12, 1u8..=28).prop_map(|(y, m, d)| format!("{y:04}-{m:02}-{d:02}"))
}

fn field() -> impl Strategy<Value = Field> {
    let value = prop_oneof![
        prefixed("[ -~\u{e9}\u{301}\u{fc}\u{20ac}]{0,24}").prop_map(Value::Text),
        prefixed("[ -~\t\u{e9}\u{301}\u{20ac}]{0,24}").prop_map(Value::Secret),
        prefixed("[ -~\t\r\n\u{e9}\u{20ac}]{0,40}").prop_map(Value::Multiline),
        date().prop_map(Value::Date),
    ];
    (label(), value, prop::option::of(date())).prop_map(|(label, value, expiry)| Field {
        label,
        value,
        expiry,
    })
}

fn entry() -> impl Strategy<Value = Entry> {
    ("[!-~]{0,12}", prop::collection::vec(field(), 0..=SLOTS))
        .prop_map(|(password, fields)| Entry { password, fields })
}

/// An entry with one ASCII custom secret at `secret_at`, and the byte to change.
struct DupCase {
    entry: Entry,
    secret_at: usize,
    byte_at: prop::sample::Index,
}

impl fmt::Debug for DupCase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DupCase")
            .field("entry", &self.entry)
            .field("secret_at", &self.secret_at)
            .field("byte_at", &self.byte_at)
            .finish()
    }
}

fn dup_case() -> impl Strategy<Value = DupCase> {
    (
        "[!-~]{0,12}",
        prop::collection::vec(field(), 0..SLOTS),
        "[!-~]{1,16}",
        any::<bool>(),
        any::<prop::sample::Index>(),
        any::<prop::sample::Index>(),
    )
        .prop_map(|(password, mut fields, secret, multiline, at, byte_at)| {
            let secret_at = at.index(fields.len() + 1);
            let value = if multiline {
                Value::Multiline(secret)
            } else {
                Value::Secret(secret)
            };
            fields.insert(
                secret_at,
                Field {
                    label: "Key".to_owned(),
                    value,
                    expiry: None,
                },
            );
            DupCase {
                entry: Entry { password, fields },
                secret_at,
                byte_at,
            }
        })
}

// ---------------------------------------------------------------- seed CSV

const BUILTIN: [&str; 14] = [
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

/// The 14 built-in columns, then four per custom-field slot.
fn columns() -> Vec<String> {
    let mut out: Vec<String> = BUILTIN.iter().map(|c| (*c).to_owned()).collect();
    for n in 1..=SLOTS {
        for part in ["label", "kind", "value", "expiry"] {
            out.push(format!("field{n}_{part}"));
        }
    }
    out
}

/// RFC 4180: wrap in quotes and double every quote.
fn quote(out: &mut String, cell: &str) {
    out.push('"');
    out.push_str(&cell.replace('"', "\"\""));
    out.push('"');
}

fn push_line(out: &mut String, cells: &[String]) {
    for (i, c) in cells.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        quote(out, c);
    }
    out.push_str("\r\n");
}

/// A title unique across every case, so no row is a duplicate by accident and the
/// export order does not depend on item ids.
fn title(case: usize, i: usize) -> String {
    format!("r{case}.{i}")
}

/// The entries as logins in a CSV file, every cell quoted.
fn seed_csv(case: usize, entries: &[Entry]) -> String {
    let header = columns();
    let mut out = String::new();
    push_line(&mut out, &header);
    for (i, e) in entries.iter().enumerate() {
        let mut cells: Vec<String> = vec![
            title(case, i),
            String::new(),
            e.password.clone(),
            String::new(),
            String::new(),
            String::new(),
            "login".to_owned(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "false".to_owned(),
            (NOW - 100).to_string(),
            (NOW - 50).to_string(),
        ];
        for f in &e.fields {
            cells.push(f.label.clone());
            cells.push(f.value.kind_cell().to_owned());
            cells.push(f.value.cell().to_owned());
            cells.push(f.expiry.clone().unwrap_or_default());
        }
        cells.resize(header.len(), String::new());
        push_line(&mut out, &cells);
    }
    out
}

// ---------------------------------------------------------------- checks

fn same_date(got: Option<holm_core::fields::CalendarDate>, want: Option<&String>) -> bool {
    match (got, want) {
        (None, None) => true,
        (Some(d), Some(s)) => format_date(d).as_slice() == s.as_bytes(),
        _ => false,
    }
}

/// Labels, kinds, value bytes and expiry, in order.
fn check_fields(got: &[CustomField], want: &[Field]) -> Result<(), TestCaseError> {
    prop_assert_eq!(got.len(), want.len());
    for (i, (g, w)) in got.iter().zip(want).enumerate() {
        prop_assert!(
            g.label().as_bytes() == w.label.as_bytes(),
            "label differs in field {}",
            i
        );
        prop_assert_eq!(g.kind(), w.value.kind());
        let same = match (g.value(), &w.value) {
            (FieldValue::Text(t), Value::Text(s)) => t.as_str().as_bytes() == s.as_bytes(),
            (FieldValue::Secret(t), Value::Secret(s))
            | (FieldValue::MultilineSecret(t), Value::Multiline(s)) => {
                t.expose().as_bytes() == s.as_bytes()
            }
            (FieldValue::Date(d), Value::Date(s)) => format_date(*d).as_slice() == s.as_bytes(),
            _ => false,
        };
        prop_assert!(same, "value differs in field {}", i);
        prop_assert!(
            same_date(g.expiry(), w.expiry.as_ref()),
            "expiry differs in field {}",
            i
        );
    }
    Ok(())
}

/// Finds the active item titled `item_title` and compares it with `e`.
fn check_entry(s: &Session<Mem>, item_title: &str, e: &Entry) -> Result<(), TestCaseError> {
    let Some(item) = s.active_items().unwrap().find(|i| i.title() == item_title) else {
        return Err(TestCaseError::fail("imported item not found"));
    };
    match item.data() {
        ItemData::Login { password, .. } => {
            prop_assert!(
                password.expose().as_bytes() == e.password.as_bytes(),
                "password differs"
            );
        }
        _ => prop_assert!(false, "imported item is not a login"),
    }
    check_fields(item.fields(), &e.fields)
}

fn export(s: &mut Session<Mem>, format: ImportFormat) -> SecretBuf {
    match format {
        ImportFormat::Csv => s.export_csv(&password()),
        ImportFormat::Json => s.export_json(&password()),
    }
    .unwrap()
}

// ---------------------------------------------------------------- round trip

/// Properties 1 to 4 for one format. Both vaults live for the whole run, so B always
/// holds exactly the items of A and their exports can be compared whole.
fn round_trip(format: ImportFormat) {
    let a = RefCell::new(new_session());
    let b = RefCell::new(new_session());
    let case = Cell::new(0usize);
    runner()
        .run(&prop::collection::vec(entry(), 1..4), |entries| {
            let n = case.get() + 1;
            case.set(n);
            let mut a = a.borrow_mut();
            let mut b = b.borrow_mut();

            // Seed A.
            let src = seed_csv(n, &entries);
            let batch = parse(src.as_bytes(), ImportFormat::Csv).unwrap();
            prop_assert!(batch.issues().is_empty(), "{:?}", batch.issues());
            let report = a.import(batch).unwrap();
            prop_assert_eq!(report.imported, entries.len());
            for (i, e) in entries.iter().enumerate() {
                check_entry(&a, &title(n, i), e)?;
            }

            // (1) and (2): export A, import into B, every field comes back.
            let first = export(&mut a, format);
            let batch = parse(first.expose(), format).unwrap();
            prop_assert!(batch.issues().is_empty(), "{:?}", batch.issues());
            let report = b.import(batch).unwrap();
            prop_assert_eq!(report.imported, entries.len());
            for (i, e) in entries.iter().enumerate() {
                check_entry(&b, &title(n, i), e)?;
            }

            // (3): the re-export of B is the export of A, byte for byte.
            let second = export(&mut b, format);
            prop_assert!(
                first.expose() == second.expose(),
                "re-export differs from the first export"
            );

            // (4): the export back into A adds nothing.
            let batch = parse(first.expose(), format).unwrap();
            let ready = batch.ready();
            let report = a.import(batch).unwrap();
            prop_assert_eq!(report.imported, 0);
            prop_assert_eq!(report.duplicates, ready);
            Ok(())
        })
        .unwrap();
}

#[test]
fn csv_round_trip_keeps_custom_fields() {
    round_trip(ImportFormat::Csv);
}

#[test]
fn json_round_trip_keeps_custom_fields() {
    round_trip(ImportFormat::Json);
}

// ---------------------------------------------------------------- dedup

/// Property 5: one changed byte in one custom secret makes the row new.
#[test]
fn changed_custom_secret_is_not_a_duplicate() {
    let a = RefCell::new(new_session());
    let case = Cell::new(0usize);
    runner()
        .run(&dup_case(), |c| {
            let n = case.get() + 1;
            case.set(n);
            let mut a = a.borrow_mut();

            let src = seed_csv(n, std::slice::from_ref(&c.entry));
            let batch = parse(src.as_bytes(), ImportFormat::Csv).unwrap();
            prop_assert!(batch.issues().is_empty(), "{:?}", batch.issues());
            prop_assert_eq!(a.import(batch).unwrap().imported, 1);

            // The same row again is a duplicate.
            let batch = parse(src.as_bytes(), ImportFormat::Csv).unwrap();
            let preview = a.preview_import(&batch).unwrap();
            prop_assert_eq!(preview.duplicates, 1);
            prop_assert_eq!(preview.logins, 0);

            // One byte of the custom secret changed, staying printable ASCII.
            let mut changed = c.entry.clone();
            let value = match &mut changed.fields[c.secret_at].value {
                Value::Secret(s) | Value::Multiline(s) => s,
                _ => return Err(TestCaseError::fail("planted field is not a secret")),
            };
            let mut bytes = std::mem::take(value).into_bytes();
            let k = c.byte_at.index(bytes.len());
            bytes[k] = if bytes[k] == b'~' { b'!' } else { bytes[k] + 1 };
            *value = String::from_utf8(bytes).unwrap();

            let src = seed_csv(n, std::slice::from_ref(&changed));
            let batch = parse(src.as_bytes(), ImportFormat::Csv).unwrap();
            prop_assert!(batch.issues().is_empty(), "{:?}", batch.issues());
            let preview = a.preview_import(&batch).unwrap();
            prop_assert_eq!(preview.duplicates, 0);
            prop_assert_eq!(preview.logins, 1);
            let report = a.import(batch).unwrap();
            prop_assert_eq!(report.imported, 1);
            prop_assert_eq!(report.duplicates, 0);
            Ok(())
        })
        .unwrap();
}
