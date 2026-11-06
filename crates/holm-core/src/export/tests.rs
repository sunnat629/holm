use super::*;
use crate::category::CategoryId;
use crate::clock::FakeClock;
use crate::fields::{
    FieldKind, FieldValue, format_date, parse_date, parse_recovery_codes, try_field,
};
use crate::import::{ImportFormat, RowIssue, RowProblem, parse};
use crate::item::{Item, ItemData, ItemId, ItemInput, ItemType, Timestamp};
use crate::plain::{Cell, CsvReader, ROW_END, quoted_len};
use crate::rules::{FieldError, MAX_RECOVERY_CODES};
use crate::store::MemStore;
use crate::text::{GatedSecret, SecretText, Text};
use crate::throttle::FREE_FAILURES;
use holm_crypto::kdf::KdfParams;
use std::time::Duration;

type S = Session<MemStore>;

const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";
const WRONG: &str = "not-the-Right-password-EXAMPLE-0";
const NOW: i64 = 1_700_000_000;
/// The Review Focus password: spaces at both ends, a tab and a decomposed accent.
const ODD_PW: &str = " pa\u{301}ss\tword ";
/// The quoted header row, including the forty custom-field columns.
fn header() -> String {
    let quoted: Vec<String> = EXPORT_COLUMNS.iter().map(|c| format!("\"{c}\"")).collect();
    format!("{}\r\n", quoted.join(","))
}

/// Appends an empty quoted cell for each custom-field column. `row` is a 14-cell oracle.
fn with_empty_custom(row: &str) -> String {
    let bare = row.strip_suffix(ROW_END).expect("row ends");
    let extra = (EXPORT_COLUMNS.len() - 14) * 3 + ROW_END.len();
    let mut out = String::with_capacity(bare.len() + extra);
    out.push_str(bare);
    for _ in 14..EXPORT_COLUMNS.len() {
        out.push_str(",\"\"");
    }
    out.push_str(ROW_END);
    out
}

fn pw(s: &str) -> MasterPassword {
    MasterPassword::new(s.to_owned())
}

fn t(s: &str) -> Text {
    Text::new(s.to_owned())
}

fn st(s: &str) -> SecretText {
    SecretText::new(s.to_owned())
}

fn fresh_at(now: i64) -> (S, FakeClock) {
    let clock = FakeClock::default();
    clock.set_unix(now);
    let mut s = Session::new(MemStore::default(), Box::new(clock.clone()));
    s.create(&pw(PW), &KdfParams::FLOOR).unwrap();
    (s, clock)
}

fn fresh() -> S {
    fresh_at(NOW).0
}

fn input(title: &str, category: Option<CategoryId>, favourite: bool, data: ItemData) -> ItemInput {
    ItemInput {
        fields: Vec::new(),
        title: t(title),
        category,
        favourite,
        data,
    }
}

fn login(title: &str, password: &str) -> ItemInput {
    input(
        title,
        None,
        false,
        ItemData::Login {
            username: t("user@example.com"),
            password: st(password),
            urls: vec![t("https://example.com")],
            notes: st(""),
        },
    )
}

fn category(s: &S, name: &str) -> CategoryId {
    s.categories()
        .unwrap()
        .iter()
        .find(|c| c.name() == name)
        .unwrap()
        .id()
}

fn set_times(s: &mut S, id: ItemId, created: i64, updated: i64) {
    let data = &mut s.unlocked_mut().unwrap().data;
    let item = data.items.iter_mut().find(|i| i.id == id).unwrap();
    item.created = Timestamp(created);
    item.updated = Timestamp(updated);
}

fn export_text(s: &mut S) -> String {
    let buf = s.export_csv(&pw(PW)).unwrap();
    String::from_utf8(buf.expose().to_vec()).unwrap()
}

/// Every record of `src`, decoded by the import reader.
fn records(src: &str) -> Vec<Vec<String>> {
    let mut reader = CsvReader::new(src);
    let mut cells: Vec<Cell> = Vec::new();
    let mut out = Vec::new();
    while reader.next_record(&mut cells, 64).unwrap().is_some() {
        out.push(cells.iter().map(|c| c.as_str().to_owned()).collect());
    }
    out
}

/// Every field of one item as plain values, the phrase from `reveal_phrase`.
#[derive(Debug, PartialEq)]
struct Snap {
    title: String,
    kind: ItemType,
    fields: Vec<String>,
    favourite: bool,
    created: Timestamp,
    updated: Timestamp,
    category: Option<String>,
}

/// The active items of `s`, by title.
fn snaps(s: &mut S) -> Vec<Snap> {
    let ids: Vec<ItemId> = s.active_items().unwrap().map(|i| i.id()).collect();
    let mut out = Vec::new();
    for id in ids {
        let item = s.item(id).unwrap();
        let category = item.category().map(|c| {
            s.categories()
                .unwrap()
                .iter()
                .find(|x| x.id() == c)
                .unwrap()
                .name()
                .to_owned()
        });
        let fields: Vec<String> = match item.data() {
            ItemData::Login {
                username,
                password,
                urls,
                notes,
            } => [username.as_str(), password.expose(), notes.expose()]
                .into_iter()
                .chain(urls.iter().map(Text::as_str))
                .map(str::to_owned)
                .collect(),
            ItemData::CryptoAddress {
                chain,
                address,
                memo,
                notes,
            } => [
                chain.as_str(),
                address.expose(),
                memo.expose(),
                notes.expose(),
            ]
            .map(str::to_owned)
            .to_vec(),
            ItemData::RecoveryPhrase { notes, .. } => vec![notes.expose().to_owned()],
            ItemData::SecureNote { body } => vec![body.expose().to_owned()],
        };
        let mut snap = Snap {
            title: item.title().to_owned(),
            kind: item.item_type(),
            fields,
            favourite: item.favourite(),
            created: item.created(),
            updated: item.updated(),
            category,
        };
        if snap.kind == ItemType::RecoveryPhrase {
            snap.fields
                .push(s.reveal_phrase(id, &pw(PW)).unwrap().to_owned());
        }
        out.push(snap);
    }
    out.sort_by(|a, b| a.title.cmp(&b.title));
    out
}

/// Exports `s`, reads the file back and imports it into a fresh vault.
fn reimport(s: &mut S) -> S {
    let buf = s.export_csv(&pw(PW)).unwrap();
    let batch = parse(buf.expose(), ImportFormat::Csv).unwrap();
    assert!(batch.issues().is_empty(), "{:?}", batch.issues());
    let (mut other, _) = fresh_at(NOW + 1_000);
    other.import(batch).unwrap();
    other
}

/// One item of each type, with built-in categories, favourites and fixed times.
fn every_type(s: &mut S) {
    let work = category(s, "Work");
    let personal = category(s, "Personal");
    let l = s
        .add_item(input(
            "A login",
            Some(work),
            true,
            ItemData::Login {
                username: t("user@example.com"),
                password: st("EXAMPLE-pw"),
                urls: vec![t("https://a.example.com"), t("https://b.example.com")],
                notes: st("n1"),
            },
        ))
        .unwrap();
    set_times(s, l, 100, 200);
    let c = s
        .add_item(input(
            "B crypto",
            None,
            false,
            ItemData::CryptoAddress {
                chain: t("EXAMPLE-chain"),
                address: st("EXAMPLE-addr"),
                memo: st("memo-1"),
                notes: st("cn"),
            },
        ))
        .unwrap();
    set_times(s, c, 300, 300);
    let p = s
        .add_item(input(
            "C phrase",
            Some(personal),
            false,
            ItemData::RecoveryPhrase {
                phrase: GatedSecret::new(st("example words EXAMPLE")),
                notes: st("pn"),
            },
        ))
        .unwrap();
    set_times(s, p, -5, 7);
    s.add_item(input(
        "D note",
        None,
        false,
        ItemData::SecureNote {
            body: st("Body\r\nline"),
        },
    ))
    .unwrap();
}

#[test]
fn export_needs_password_and_is_throttled() {
    let (mut s, clock) = fresh_at(NOW);
    s.add_item(login("a", "EXAMPLE-pw")).unwrap();
    for n in 1..=FREE_FAILURES {
        assert_eq!(
            s.export_csv(&pw(WRONG)).unwrap_err(),
            CoreError::WrongPassword
        );
        assert_eq!(s.throttle_status().consecutive_failures, n);
    }
    assert!(matches!(
        s.export_csv(&pw(PW)),
        Err(CoreError::Throttled { .. })
    ));
    clock.advance(Duration::from_secs(2));
    assert!(export_text(&mut s).contains("EXAMPLE-pw"));
    assert_eq!(s.throttle_status().consecutive_failures, 0);

    s.lock();
    assert_eq!(s.export_csv(&pw(PW)).unwrap_err(), CoreError::Locked);
}

#[test]
fn export_excludes_trash() {
    let mut s = fresh();
    s.add_item(login("kept", "EXAMPLE-kept")).unwrap();
    let gone = s.add_item(login("gone", "EXAMPLE-gone")).unwrap();
    s.trash(gone).unwrap();
    let text = export_text(&mut s);
    let rows = records(&text);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1][0], "kept");
    assert!(!text.contains("EXAMPLE-gone"));
    assert!(!text.contains("gone"));
}

#[test]
fn export_header_exact() {
    let mut s = fresh();
    assert_eq!(export_text(&mut s), header());
    let joined: Vec<String> = EXPORT_COLUMNS.iter().map(|c| format!("\"{c}\"")).collect();
    assert_eq!(format!("{}\r\n", joined.join(",")), header());
}

#[test]
fn export_quotes_everything() {
    let mut s = fresh();
    s.add_item(input(
        "Say \"hi\"",
        None,
        false,
        ItemData::Login {
            username: t("a,b"),
            password: st("p\"w,1"),
            urls: vec![t("https://example.com/?q=1,2")],
            notes: st("l1\nl2"),
        },
    ))
    .unwrap();
    let text = export_text(&mut s);
    let row = "\"Say \"\"hi\"\"\",\"a,b\",\"p\"\"w,1\",\"https://example.com/?q=1,2\",\"l1\nl2\",\"\",\"login\",\"\",\"\",\"\",\"\",\"false\",\"1700000000\",\"1700000000\"\r\n";
    assert_eq!(text, format!("{}{}", header(), with_empty_custom(row)));
}

#[test]
fn export_row_layout_per_type() {
    let mut s = fresh();
    every_type(&mut s);
    let mut expected = header();
    for row in [
        "\"A login\",\"user@example.com\",\"EXAMPLE-pw\",\"https://a.example.com\nhttps://b.example.com\",\"n1\",\"Work\",\"login\",\"\",\"\",\"\",\"\",\"true\",\"100\",\"200\"\r\n",
        "\"B crypto\",\"\",\"\",\"\",\"cn\",\"\",\"crypto\",\"EXAMPLE-chain\",\"EXAMPLE-addr\",\"memo-1\",\"\",\"false\",\"300\",\"300\"\r\n",
        "\"C phrase\",\"\",\"\",\"\",\"pn\",\"Personal\",\"recovery\",\"\",\"\",\"\",\"example words EXAMPLE\",\"false\",\"-5\",\"7\"\r\n",
        "\"D note\",\"\",\"\",\"\",\"Body\r\nline\",\"\",\"note\",\"\",\"\",\"\",\"\",\"false\",\"1700000000\",\"1700000000\"\r\n",
    ] {
        expected.push_str(&with_empty_custom(row));
    }
    assert_eq!(export_text(&mut s), expected);
}

#[test]
fn export_rows_in_title_order() {
    let mut s = fresh();
    for title in ["Zeta", "alpha", "Beta"] {
        s.add_item(login(title, "EXAMPLE-pw")).unwrap();
    }
    let titles: Vec<String> = records(&export_text(&mut s))
        .into_iter()
        .skip(1)
        .map(|r| r[0].clone())
        .collect();
    assert_eq!(titles, ["alpha", "Beta", "Zeta"]);
}

#[test]
fn export_does_not_escape_formulas() {
    const FORMULAS: [&str; 4] = ["=SUM(A1)", "+1", "-1", "@x"];
    let mut s = fresh();
    for (i, f) in FORMULAS.iter().enumerate() {
        s.add_item(login(&format!("formula {i}"), f)).unwrap();
    }
    let text = export_text(&mut s);
    for f in FORMULAS {
        assert!(text.contains(&format!(",\"{f}\",")), "{f} not verbatim");
        assert!(!text.contains(&format!("'{f}")), "{f} escaped");
    }
    let mut other = reimport(&mut s);
    assert_eq!(snaps(&mut other), snaps(&mut s));
    let passwords: Vec<String> = snaps(&mut other)
        .into_iter()
        .map(|snap| snap.fields[1].clone())
        .collect();
    assert_eq!(passwords, FORMULAS);
}

#[test]
fn export_import_roundtrip_all_types() {
    let mut s = fresh();
    every_type(&mut s);
    let odd = s
        .add_item(input(
            "E odd password",
            Some(category(&s, "Community")),
            true,
            ItemData::Login {
                username: t(""),
                password: st(ODD_PW),
                urls: vec![],
                notes: st("\"quoted\", with comma\r\nand lines\n"),
            },
        ))
        .unwrap();
    set_times(&mut s, odd, 1, 1);
    let mut before = snaps(&mut s);
    assert_eq!(before.len(), 5);
    // The exported pre-epoch time is clamped on import.
    before
        .iter_mut()
        .find(|item| item.title == "C phrase")
        .unwrap()
        .created = Timestamp(0);

    let mut other = reimport(&mut s);
    let after = snaps(&mut other);
    assert_eq!(after, before);
    let odd_after = after.iter().find(|x| x.title == "E odd password").unwrap();
    assert_eq!(odd_after.fields[1].as_bytes(), ODD_PW.as_bytes());
}

#[test]
fn export_warning_names_spreadsheets() {
    assert!(EXPORT_WARNING.contains("plain text"));
    assert!(EXPORT_WARNING.contains("spreadsheet"));
}

#[test]
fn export_buffer_allocated_once() {
    let mut s = fresh();
    every_type(&mut s);
    s.add_item(login("q\"u\"o\"tes", "\"\"\"")).unwrap();
    let buf = s.export_csv(&pw(PW)).unwrap();
    let text = core::str::from_utf8(buf.expose()).unwrap();
    let rows = records(text);
    assert_eq!(rows.len(), 6);
    let separators = EXPORT_COLUMNS.len() - 1 + ROW_END.len();
    let expected: usize = rows
        .iter()
        .map(|r| r.iter().map(|c| quoted_len(c)).sum::<usize>() + separators)
        .sum();
    assert_eq!(buf.expose().len(), expected);

    // The buffer never grew: it is still at the capacity it was allocated with.
    let data = &s.unlocked().unwrap().data;
    let items: Vec<&Item> = data.items.iter().collect();
    let out = build(&items, &data.categories);
    assert_eq!(out.len(), expected);
    assert_eq!(out.capacity(), out.len());
    assert_eq!(write_csv(&items, &data.categories).expose(), out.as_bytes());
}

#[test]
fn write_csv_with_no_items_is_the_header() {
    assert_eq!(write_csv(&[], &[]).expose(), header().as_bytes());
}

const FIRST_COLUMNS: [&str; 14] = [
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

const MULTILINE: &str = "one \"two\"\nthree\\four";

fn sample_fields() -> Vec<crate::fields::CustomField> {
    vec![
        try_field(t("Note"), FieldValue::Text(t("public note")), None).unwrap(),
        try_field(
            t("Pin"),
            FieldValue::Secret(st("EXAMPLE-field-secret")),
            None,
        )
        .unwrap(),
        try_field(t("Key"), FieldValue::MultilineSecret(st(MULTILINE)), None).unwrap(),
        try_field(
            t("When"),
            FieldValue::Date(parse_date("2026-11-05").expect("date")),
            Some(parse_date("2026-12-01").expect("date")),
        )
        .unwrap(),
    ]
}

fn by_title<'a>(s: &'a S, title: &str) -> &'a Item {
    s.active_items()
        .unwrap()
        .find(|item| item.title() == title)
        .unwrap()
}

fn assert_sample_fields(item: &Item) {
    let fields = item.fields();
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0].label(), "Note");
    assert_eq!(fields[0].kind(), FieldKind::Text);
    assert_eq!(fields[0].expiry(), None);
    match fields[0].value() {
        FieldValue::Text(value) => assert_eq!(value.as_str(), "public note"),
        _ => panic!("text"),
    }
    assert_eq!(fields[1].label(), "Pin");
    assert_eq!(fields[1].kind(), FieldKind::Secret);
    match fields[1].value() {
        FieldValue::Secret(value) => assert_eq!(value.expose().as_bytes(), b"EXAMPLE-field-secret"),
        _ => panic!("secret"),
    }
    assert_eq!(fields[2].label(), "Key");
    assert_eq!(fields[2].kind(), FieldKind::MultilineSecret);
    match fields[2].value() {
        FieldValue::MultilineSecret(value) => assert_eq!(value.expose(), MULTILINE),
        _ => panic!("multiline"),
    }
    assert_eq!(fields[3].label(), "When");
    assert_eq!(fields[3].kind(), FieldKind::Date);
    match fields[3].value() {
        FieldValue::Date(date) => assert_eq!(format_date(*date), *b"2026-11-05"),
        _ => panic!("date"),
    }
    assert_eq!(fields[3].expiry().map(format_date), Some(*b"2026-12-01"));
}

fn vault_with_sample() -> S {
    let mut s = fresh();
    let id = s.add_item(login("Fields", "EXAMPLE-pw")).unwrap();
    s.set_custom_fields(id, sample_fields()).unwrap();
    let gone = s.add_item(login("gone", "EXAMPLE-gone")).unwrap();
    s.trash(gone).unwrap();
    s
}

#[test]
fn export_header_has_54_columns() {
    let mut s = fresh();
    let rows = records(&export_text(&mut s));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], EXPORT_COLUMNS);
    assert_eq!(EXPORT_COLUMNS.len(), 54);
    assert_eq!(&EXPORT_COLUMNS[..14], &FIRST_COLUMNS);
    assert_eq!(EXPORT_COLUMNS[14], "field1_label");
    assert_eq!(*EXPORT_COLUMNS.last().unwrap(), "field10_expiry");
}

#[test]
fn export_import_roundtrip_custom_fields() {
    let mut s = vault_with_sample();
    let text = export_text(&mut s);
    let rows = records(&text);
    assert_eq!(rows.len(), 2);
    let data = &rows[1];
    assert_eq!(data[0], "Fields");
    assert_eq!(data[14..18], ["Note", "text", "public note", ""]);
    assert_eq!(data[18..22], ["Pin", "secret", "EXAMPLE-field-secret", ""]);
    assert_eq!(data[22..26], ["Key", "multiline", MULTILINE, ""]);
    assert_eq!(data[26..30], ["When", "date", "2026-11-05", "2026-12-01"]);
    assert!(data[30].is_empty());
    assert!(!text.contains("EXAMPLE-gone"));

    let other = reimport(&mut s);
    assert_sample_fields(by_title(&other, "Fields"));
}

#[test]
fn json_export_import_roundtrip() {
    assert_eq!(write_json(&[], &[]).expose(), b"[]");
    let mut s = vault_with_sample();
    let buf = s.export_json(&pw(PW)).unwrap();
    let text = core::str::from_utf8(buf.expose()).unwrap();
    assert!(text.starts_with("[{"));
    assert!(text.ends_with("}]"));
    assert!(!text.contains('\n'));
    assert!(text.contains("\\\""));
    assert!(text.contains("\\n"));
    assert!(text.contains("\\\\"));
    assert!(text.contains("\"field5_label\":\"\""));
    assert!(!text.contains("EXAMPLE-gone"));
    let mut at = 0;
    for key in [
        "title",
        "username",
        "updated",
        "field1_label",
        "field1_kind",
        "field1_value",
        "field1_expiry",
        "field10_expiry",
    ] {
        let found = text.find(&format!("\"{key}\":")).unwrap();
        assert!(found > at, "{key}");
        at = found;
    }

    let batch = parse(text.as_bytes(), ImportFormat::Json).unwrap();
    assert!(batch.issues().is_empty());
    let (mut other, _) = fresh_at(NOW + 1_000);
    other.import(batch).unwrap();
    assert_sample_fields(by_title(&other, "Fields"));
}

#[test]
fn formula_still_unescaped() {
    const FORMULAS: [&str; 4] = ["=SUM(A1)", "+1", "-1", "@x"];
    let mut s = fresh();
    let id = s.add_item(login("formula field", "plain")).unwrap();
    let fields = FORMULAS
        .iter()
        .enumerate()
        .map(|(i, formula)| {
            try_field(t(&format!("P{i}")), FieldValue::Secret(st(formula)), None).unwrap()
        })
        .collect();
    s.set_custom_fields(id, fields).unwrap();
    let text = export_text(&mut s);
    for formula in FORMULAS {
        assert!(text.contains(&format!(",\"{formula}\",")), "{formula}");
        assert!(!text.contains(&format!("'{formula}")), "{formula}");
    }
    let other = reimport(&mut s);
    let item = by_title(&other, "formula field");
    assert_eq!(item.fields().len(), 4);
    for (field, formula) in item.fields().iter().zip(FORMULAS) {
        match field.value() {
            FieldValue::Secret(value) => assert_eq!(value.expose(), formula),
            _ => panic!("secret"),
        }
    }
}

fn codes_field() -> crate::fields::CustomField {
    let mut codes = parse_recovery_codes("EXAMPLE-c1\nEXAMPLE-c2\nEXAMPLE-c3").unwrap();
    codes[1].set_used(true);
    try_field(t("Backup"), FieldValue::RecoveryCodes(codes), None).unwrap()
}

fn assert_codes(item: &Item) {
    let fields = item.fields();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].label(), "Backup");
    assert_eq!(fields[0].kind(), FieldKind::RecoveryCodes);
    let FieldValue::RecoveryCodes(codes) = fields[0].value() else {
        panic!("codes");
    };
    let got: Vec<(&str, bool)> = codes
        .iter()
        .map(|c| (c.code().expose(), c.used()))
        .collect();
    assert_eq!(
        got,
        [
            ("EXAMPLE-c1", false),
            ("EXAMPLE-c2", true),
            ("EXAMPLE-c3", false)
        ]
    );
}

#[test]
fn recovery_codes_roundtrip_csv_and_json() {
    let mut s = fresh();
    let id = s.add_item(login("Codes", "EXAMPLE-pw")).unwrap();
    s.set_custom_fields(id, vec![codes_field()]).unwrap();
    let rows = records(&export_text(&mut s));
    assert_eq!(
        rows[1][14..18],
        ["Backup", "codes", "EXAMPLE-c1\n*EXAMPLE-c2\nEXAMPLE-c3", ""]
    );

    for format in [ImportFormat::Csv, ImportFormat::Json] {
        let buf = match format {
            ImportFormat::Csv => s.export_csv(&pw(PW)),
            ImportFormat::Json => s.export_json(&pw(PW)),
        }
        .unwrap();
        let batch = parse(buf.expose(), format).unwrap();
        assert!(batch.issues().is_empty(), "{:?}", batch.issues());
        let (mut other, _) = fresh_at(NOW + 1_000);
        other.import(batch).unwrap();
        assert_codes(by_title(&other, "Codes"));

        let again = parse(buf.expose(), format).unwrap();
        let report = other.import(again).unwrap();
        assert_eq!(report.imported, 0, "{format:?}");
        assert_eq!(report.duplicates, 1, "{format:?}");
    }
}

#[test]
fn too_many_codes_refused() {
    let codes: Vec<String> = (0..=MAX_RECOVERY_CODES)
        .map(|i| format!("EXAMPLE-{i}"))
        .collect();
    let src = format!(
        "title,password,field1_label,field1_kind,field1_value\r\nCodes,EXAMPLE-pw,Backup,codes,\"{}\"\r\n",
        codes.join("\n")
    );
    let batch = parse(src.as_bytes(), ImportFormat::Csv).unwrap();
    assert_eq!(batch.ready(), 0);
    assert_eq!(
        batch.issues(),
        [RowIssue {
            row: 1,
            problem: RowProblem::Field(FieldError::BadCodeCount),
        }]
    );
}

#[test]
fn export_json_needs_password() {
    let (mut s, clock) = fresh_at(NOW);
    s.add_item(login("a", "EXAMPLE-pw")).unwrap();
    for n in 1..=FREE_FAILURES {
        assert_eq!(
            s.export_json(&pw(WRONG)).unwrap_err(),
            CoreError::WrongPassword
        );
        assert_eq!(s.throttle_status().consecutive_failures, n);
    }
    assert!(matches!(
        s.export_json(&pw(PW)),
        Err(CoreError::Throttled { .. })
    ));
    clock.advance(Duration::from_secs(2));
    let buf = s.export_json(&pw(PW)).unwrap();
    let text = core::str::from_utf8(buf.expose()).unwrap();
    assert!(text.contains("EXAMPLE-pw"));
    assert_eq!(s.throttle_status().consecutive_failures, 0);

    s.lock();
    assert_eq!(s.export_json(&pw(PW)).unwrap_err(), CoreError::Locked);
}
