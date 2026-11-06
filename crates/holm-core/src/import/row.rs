//! Column names, and turning one row of cells into an item.
//!
//! The rules here are the same for CSV and JSON. A row's problem is a
//! [`RowProblem`], which names the problem and never a value. Holm never guesses
//! where a secret goes: a phrase comes only from the `recovery` column, and a secret
//! cell the row's type does not use is an error, not silently dropped.
//!
//! Custom fields are four cells a slot (`label`, `kind`, `value`, `expiry`), packed
//! from slot 1. A later slot filled while an earlier one is empty is a row problem.
//! Kind and date cells are trimmed, then checked. A text or secret value is moved
//! out of its cell with no second copy.

use crate::fields::{
    CalendarDate, CustomField, FieldKind, FieldValue, codes_from_cell, parse_date, try_field,
};
use crate::item::{ItemData, ItemInput, Timestamp};
use crate::plain::Cell;
use crate::rules::{MAX_CUSTOM_FIELDS, MAX_URLS};
use crate::text::{GatedSecret, SecretText, Text};

use super::{Dialect, ImportRow, RowProblem};

/// A Holm column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Col {
    Title,
    Username,
    Password,
    Url,
    Notes,
    Category,
    Type,
    Chain,
    Address,
    Memo,
    Recovery,
    Favourite,
    Created,
    Updated,
    Field1Label,
    Field1Kind,
    Field1Value,
    Field1Expiry,
    Field2Label,
    Field2Kind,
    Field2Value,
    Field2Expiry,
    Field3Label,
    Field3Kind,
    Field3Value,
    Field3Expiry,
    Field4Label,
    Field4Kind,
    Field4Value,
    Field4Expiry,
    Field5Label,
    Field5Kind,
    Field5Value,
    Field5Expiry,
    Field6Label,
    Field6Kind,
    Field6Value,
    Field6Expiry,
    Field7Label,
    Field7Kind,
    Field7Value,
    Field7Expiry,
    Field8Label,
    Field8Kind,
    Field8Value,
    Field8Expiry,
    Field9Label,
    Field9Kind,
    Field9Value,
    Field9Expiry,
    Field10Label,
    Field10Kind,
    Field10Value,
    Field10Expiry,
}

/// How many Holm columns there are. The first 14 stay the built-in columns.
const COLS: usize = 54;

const _: () = assert!(COLS <= super::MAX_IMPORT_COLUMNS);
const _: () = assert!((Col::Field1Label as usize) == 14);
const _: () = assert!((Col::Field10Expiry as usize) == COLS - 1);

/// Every header name Holm reads, with its aliases. `canonical` is the name the
/// header map is keyed by, so `url` and `website` are the same column.
struct Name {
    name: &'static str,
    canonical: &'static str,
    holm: Option<Col>,
}

const fn holm(name: &'static str, canonical: &'static str, col: Col) -> Name {
    Name {
        name,
        canonical,
        holm: Some(col),
    }
}

const fn browser(name: &'static str) -> Name {
    Name {
        name,
        canonical: name,
        holm: None,
    }
}

const NAMES: [Name; 66] = [
    holm("title", "title", Col::Title),
    holm("username", "username", Col::Username),
    holm("password", "password", Col::Password),
    holm("url", "url", Col::Url),
    holm("website", "url", Col::Url),
    holm("notes", "notes", Col::Notes),
    holm("category", "category", Col::Category),
    holm("type", "type", Col::Type),
    holm("chain", "chain", Col::Chain),
    holm("address", "address", Col::Address),
    holm("memo", "memo", Col::Memo),
    holm("recovery", "recovery", Col::Recovery),
    holm("recovery_secret", "recovery", Col::Recovery),
    holm("phrase", "recovery", Col::Recovery),
    holm("favourite", "favourite", Col::Favourite),
    holm("created", "created", Col::Created),
    holm("updated", "updated", Col::Updated),
    holm("field1_label", "field1_label", Col::Field1Label),
    holm("field1_kind", "field1_kind", Col::Field1Kind),
    holm("field1_value", "field1_value", Col::Field1Value),
    holm("field1_expiry", "field1_expiry", Col::Field1Expiry),
    holm("field2_label", "field2_label", Col::Field2Label),
    holm("field2_kind", "field2_kind", Col::Field2Kind),
    holm("field2_value", "field2_value", Col::Field2Value),
    holm("field2_expiry", "field2_expiry", Col::Field2Expiry),
    holm("field3_label", "field3_label", Col::Field3Label),
    holm("field3_kind", "field3_kind", Col::Field3Kind),
    holm("field3_value", "field3_value", Col::Field3Value),
    holm("field3_expiry", "field3_expiry", Col::Field3Expiry),
    holm("field4_label", "field4_label", Col::Field4Label),
    holm("field4_kind", "field4_kind", Col::Field4Kind),
    holm("field4_value", "field4_value", Col::Field4Value),
    holm("field4_expiry", "field4_expiry", Col::Field4Expiry),
    holm("field5_label", "field5_label", Col::Field5Label),
    holm("field5_kind", "field5_kind", Col::Field5Kind),
    holm("field5_value", "field5_value", Col::Field5Value),
    holm("field5_expiry", "field5_expiry", Col::Field5Expiry),
    holm("field6_label", "field6_label", Col::Field6Label),
    holm("field6_kind", "field6_kind", Col::Field6Kind),
    holm("field6_value", "field6_value", Col::Field6Value),
    holm("field6_expiry", "field6_expiry", Col::Field6Expiry),
    holm("field7_label", "field7_label", Col::Field7Label),
    holm("field7_kind", "field7_kind", Col::Field7Kind),
    holm("field7_value", "field7_value", Col::Field7Value),
    holm("field7_expiry", "field7_expiry", Col::Field7Expiry),
    holm("field8_label", "field8_label", Col::Field8Label),
    holm("field8_kind", "field8_kind", Col::Field8Kind),
    holm("field8_value", "field8_value", Col::Field8Value),
    holm("field8_expiry", "field8_expiry", Col::Field8Expiry),
    holm("field9_label", "field9_label", Col::Field9Label),
    holm("field9_kind", "field9_kind", Col::Field9Kind),
    holm("field9_value", "field9_value", Col::Field9Value),
    holm("field9_expiry", "field9_expiry", Col::Field9Expiry),
    holm("field10_label", "field10_label", Col::Field10Label),
    holm("field10_kind", "field10_kind", Col::Field10Kind),
    holm("field10_value", "field10_value", Col::Field10Value),
    holm("field10_expiry", "field10_expiry", Col::Field10Expiry),
    // Browser columns that are not Holm columns.
    browser("name"),
    browser("note"),
    browser("otpauth"),
    browser("httprealm"),
    browser("formactionorigin"),
    browser("guid"),
    browser("timecreated"),
    browser("timelastused"),
    browser("timepasswordchanged"),
];

/// The known name a header cell or JSON key stands for (trimmed, ASCII
/// case-insensitive). No copy of the text is made.
fn lookup(name: &str) -> Option<&'static Name> {
    let name = name.trim();
    NAMES.iter().find(|n| n.name.eq_ignore_ascii_case(name))
}

/// The canonical name of a header cell, if Holm knows it.
pub(super) fn canonical(name: &str) -> Option<&'static str> {
    lookup(name).map(|n| n.canonical)
}

/// The Holm column a header cell or JSON key names, if any.
pub(super) fn holm_col(name: &str) -> Option<Col> {
    lookup(name).and_then(|n| n.holm)
}

/// The cells of one row, one per Holm column, moved out of the reader's buffer.
/// Empty cells are empty strings. No `Debug`: it holds secrets.
pub(super) struct RawRow {
    cells: [Cell; COLS],
}

impl Default for RawRow {
    fn default() -> Self {
        Self {
            cells: core::array::from_fn(|_| Cell::default()),
        }
    }
}

impl RawRow {
    /// Puts a cell into column `col`. The cell is moved, not copied.
    pub(super) fn put(&mut self, col: Col, cell: Cell) {
        self.cells[col as usize] = cell;
    }

    fn get(&self, col: Col) -> &str {
        &self.cells[col as usize]
    }

    /// True if the cell has anything but whitespace.
    fn filled(&self, col: Col) -> bool {
        !self.get(col).trim().is_empty()
    }

    /// Moves the text out of the cell without a copy; the cell is left empty.
    fn take(&mut self, col: Col) -> String {
        std::mem::take(&mut *self.cells[col as usize])
    }

    fn text(&mut self, col: Col) -> Text {
        Text::new(self.take(col))
    }

    fn secret(&mut self, col: Col) -> SecretText {
        SecretText::new(self.take(col))
    }
}

/// The four item types, as named in the `type` column.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Login,
    Crypto,
    Recovery,
    Note,
}

/// The type named by a `type` cell (trimmed, ASCII case-insensitive).
fn named_kind(s: &str) -> Option<Kind> {
    const KINDS: [(&str, Kind); 9] = [
        ("login", Kind::Login),
        ("note", Kind::Note),
        ("secure_note", Kind::Note),
        ("crypto", Kind::Crypto),
        ("crypto_address", Kind::Crypto),
        ("cryptocurrency", Kind::Crypto),
        ("recovery", Kind::Recovery),
        ("recovery_phrase", Kind::Recovery),
        ("seed", Kind::Recovery),
    ];
    let s = s.trim();
    KINDS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(s))
        .map(|(_, k)| *k)
}

/// The row's type: from the `type` cell, or inferred from which cells are filled.
fn kind_of(raw: &RawRow) -> Result<Kind, RowProblem> {
    if raw.filled(Col::Type) {
        return named_kind(raw.get(Col::Type)).ok_or(RowProblem::UnknownType);
    }
    if raw.filled(Col::Recovery) {
        Ok(Kind::Recovery)
    } else if raw.filled(Col::Address) {
        Ok(Kind::Crypto)
    } else if raw.filled(Col::Password) || raw.filled(Col::Username) || raw.filled(Col::Url) {
        Ok(Kind::Login)
    } else if raw.filled(Col::Notes) {
        Ok(Kind::Note)
    } else {
        Err(RowProblem::EmptyRow)
    }
}

/// True if an item of this type keeps the field column `col`.
fn uses(kind: Kind, col: Col) -> bool {
    match kind {
        Kind::Login => matches!(col, Col::Username | Col::Password | Col::Url | Col::Notes),
        Kind::Crypto => matches!(col, Col::Chain | Col::Address | Col::Memo | Col::Notes),
        Kind::Recovery => matches!(col, Col::Recovery | Col::Notes),
        Kind::Note => matches!(col, Col::Notes),
    }
}

/// The field columns: none may be filled on a row whose type does not use it, so no
/// value in the file is dropped without a row issue.
const FIELD_COLS: [Col; 8] = [
    Col::Username,
    Col::Url,
    Col::Chain,
    Col::Password,
    Col::Notes,
    Col::Address,
    Col::Memo,
    Col::Recovery,
];

/// Custom-field cells in slot order: label, kind, value, expiry, slots 1 through 10.
const FIELD_PARTS: [Col; MAX_CUSTOM_FIELDS * 4] = [
    Col::Field1Label,
    Col::Field1Kind,
    Col::Field1Value,
    Col::Field1Expiry,
    Col::Field2Label,
    Col::Field2Kind,
    Col::Field2Value,
    Col::Field2Expiry,
    Col::Field3Label,
    Col::Field3Kind,
    Col::Field3Value,
    Col::Field3Expiry,
    Col::Field4Label,
    Col::Field4Kind,
    Col::Field4Value,
    Col::Field4Expiry,
    Col::Field5Label,
    Col::Field5Kind,
    Col::Field5Value,
    Col::Field5Expiry,
    Col::Field6Label,
    Col::Field6Kind,
    Col::Field6Value,
    Col::Field6Expiry,
    Col::Field7Label,
    Col::Field7Kind,
    Col::Field7Value,
    Col::Field7Expiry,
    Col::Field8Label,
    Col::Field8Kind,
    Col::Field8Value,
    Col::Field8Expiry,
    Col::Field9Label,
    Col::Field9Kind,
    Col::Field9Value,
    Col::Field9Expiry,
    Col::Field10Label,
    Col::Field10Kind,
    Col::Field10Value,
    Col::Field10Expiry,
];

/// `text`, `secret`, `multiline`, `date` or `codes`, any ASCII case. Anything else is
/// absent.
fn field_kind(cell: &str) -> Option<FieldKind> {
    const KINDS: [(&str, FieldKind); 5] = [
        ("text", FieldKind::Text),
        ("secret", FieldKind::Secret),
        ("multiline", FieldKind::MultilineSecret),
        ("date", FieldKind::Date),
        ("codes", FieldKind::RecoveryCodes),
    ];
    let cell = cell.trim();
    KINDS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(cell))
        .map(|(_, kind)| *kind)
}

/// Blank (after trim) is no reminder. Anything else must be `YYYY-MM-DD`.
fn field_expiry(cell: &str) -> Result<Option<CalendarDate>, RowProblem> {
    let cell = cell.trim();
    if cell.is_empty() {
        return Ok(None);
    }
    parse_date(cell).map(Some).ok_or(RowProblem::BadDate)
}

/// A date value must be `YYYY-MM-DD` after trim. An empty value is a bad date.
fn date_value(cell: &str) -> Result<CalendarDate, RowProblem> {
    parse_date(cell.trim()).ok_or(RowProblem::BadDate)
}

/// Packed custom fields for a Holm row. Browser rows do not call this.
///
/// An empty slot (no cell has anything but whitespace) is absent. A filled slot
/// after an empty one is [`RowProblem::FieldGap`]. A missing or unknown kind is
/// [`RowProblem::BadFieldKind`] before the value is moved. Text and secret bytes
/// are moved as stored. They are not trimmed.
fn field_slots(raw: &mut RawRow) -> Result<Vec<CustomField>, RowProblem> {
    let mut out = Vec::new();
    let mut gap = false;
    for slot in 0..MAX_CUSTOM_FIELDS {
        let base = slot * 4;
        let label_col = FIELD_PARTS[base];
        let kind_col = FIELD_PARTS[base + 1];
        let value_col = FIELD_PARTS[base + 2];
        let expiry_col = FIELD_PARTS[base + 3];
        let any = raw.filled(label_col)
            || raw.filled(kind_col)
            || raw.filled(value_col)
            || raw.filled(expiry_col);
        if !any {
            gap = true;
            continue;
        }
        if gap {
            return Err(RowProblem::FieldGap);
        }
        let kind = field_kind(raw.get(kind_col)).ok_or(RowProblem::BadFieldKind)?;
        let expiry = field_expiry(raw.get(expiry_col))?;
        let value = match kind {
            FieldKind::Date => FieldValue::Date(date_value(raw.get(value_col))?),
            FieldKind::Text => FieldValue::Text(raw.text(value_col)),
            FieldKind::Secret => FieldValue::Secret(raw.secret(value_col)),
            FieldKind::MultilineSecret => FieldValue::MultilineSecret(raw.secret(value_col)),
            // Each code moves into its own `SecretText`. The raw cell is wiped on drop.
            FieldKind::RecoveryCodes => FieldValue::RecoveryCodes(
                codes_from_cell(raw.get(value_col)).map_err(RowProblem::Field)?,
            ),
        };
        let label = raw.text(label_col);
        out.push(try_field(label, value, expiry).map_err(RowProblem::Field)?);
    }
    Ok(out)
}

/// `true`, `false` (ASCII case-insensitive) or blank (= false).
fn favourite(s: &str) -> Result<bool, RowProblem> {
    let s = s.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("false") {
        Ok(false)
    } else if s.eq_ignore_ascii_case("true") {
        Ok(true)
    } else {
        Err(RowProblem::BadFavourite)
    }
}

/// Decimal Unix seconds: an optional `-`, then ASCII digits, in `i64` range. Blank is
/// `None`.
fn timestamp(s: &str) -> Result<Option<Timestamp>, RowProblem> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(RowProblem::BadTimestamp);
    }
    s.parse::<i64>()
        .map(|t| Some(Timestamp(t)))
        .map_err(|_| RowProblem::BadTimestamp)
}

/// The URL cell split on `\n`, each part trimmed, empty parts dropped. At most one
/// part past [`MAX_URLS`] is kept, which is enough for validation to refuse it.
fn urls(cell: &str) -> Vec<Text> {
    cell.split('\n')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .take(MAX_URLS + 1)
        .map(|p| Text::new(p.to_owned()))
        .collect()
}

/// The host of the first URL, for a browser row with no title: the text after
/// `://`, cut at `/`, `?` or `#`, after the last `@`, without a `:port`, lowercased.
fn host(cell: &str) -> Option<String> {
    let first = cell.split('\n').map(str::trim).find(|p| !p.is_empty())?;
    let rest = first.split_once("://").map_or(first, |(_, r)| r);
    let rest = rest.split(['/', '?', '#']).next().unwrap_or("");
    let rest = rest.rsplit('@').next().unwrap_or("");
    let host = if rest.starts_with('[') {
        rest.split_inclusive(']').next().unwrap_or("")
    } else {
        rest.split(':').next().unwrap_or("")
    };
    let host = host.to_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

/// Title of a browser row that has none.
const IMPORTED_LOGIN: &str = "Imported login";

/// Turns one row into a ready item, or names its first problem.
///
/// Order: the type, then a missing address or phrase, then an unused secret column,
/// then the metadata cells, then the item rules.
pub(super) fn build(mut raw: RawRow, dialect: Dialect) -> Result<ImportRow, RowProblem> {
    let kind = if dialect == Dialect::Holm {
        kind_of(&raw)?
    } else {
        // A browser row is a login; it needs something besides a title.
        if ![Col::Username, Col::Password, Col::Url, Col::Notes]
            .into_iter()
            .any(|c| raw.filled(c))
        {
            return Err(RowProblem::EmptyRow);
        }
        Kind::Login
    };
    match kind {
        Kind::Crypto if !raw.filled(Col::Address) => return Err(RowProblem::MissingAddress),
        Kind::Recovery if !raw.filled(Col::Recovery) => return Err(RowProblem::MissingPhrase),
        _ => {}
    }
    if FIELD_COLS
        .into_iter()
        .any(|c| raw.filled(c) && !uses(kind, c))
    {
        return Err(RowProblem::UnusedField);
    }
    let favourite = favourite(raw.get(Col::Favourite))?;
    let created = timestamp(raw.get(Col::Created))?;
    let updated = timestamp(raw.get(Col::Updated))?;
    if let (Some(c), Some(u)) = (created, updated)
        && u < c
    {
        return Err(RowProblem::BadTimestamp);
    }

    let title = if dialect != Dialect::Holm && !raw.filled(Col::Title) {
        Text::new(host(raw.get(Col::Url)).unwrap_or_else(|| IMPORTED_LOGIN.to_owned()))
    } else {
        raw.text(Col::Title)
    };
    let category_name = raw.filled(Col::Category).then(|| raw.text(Col::Category));
    let data = match kind {
        Kind::Login => ItemData::Login {
            username: raw.text(Col::Username),
            password: raw.secret(Col::Password),
            urls: urls(raw.get(Col::Url)),
            notes: raw.secret(Col::Notes),
        },
        Kind::Crypto => ItemData::CryptoAddress {
            chain: raw.text(Col::Chain),
            address: raw.secret(Col::Address),
            memo: raw.secret(Col::Memo),
            notes: raw.secret(Col::Notes),
        },
        Kind::Recovery => ItemData::RecoveryPhrase {
            phrase: GatedSecret::new(raw.secret(Col::Recovery)),
            notes: raw.secret(Col::Notes),
        },
        Kind::Note => ItemData::SecureNote {
            body: raw.secret(Col::Notes),
        },
    };
    let fields = if dialect == Dialect::Holm {
        field_slots(&mut raw)?
    } else {
        Vec::new()
    };
    let input = ItemInput {
        fields,
        title,
        category: None,
        favourite,
        data,
    };
    input.validate().map_err(RowProblem::Field)?;
    Ok(ImportRow {
        input,
        category_name,
        created,
        updated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_cases() {
        assert_eq!(
            host("https://user@Accounts.Example.com:8443/login?x").as_deref(),
            Some("accounts.example.com")
        );
        assert_eq!(host("\n  \nexample.com#x").as_deref(), Some("example.com"));
        assert_eq!(host("https://[::1]:80").as_deref(), Some("[::1]"));
        assert_eq!(host("https://:80/x"), None);
        assert_eq!(host(""), None);
    }

    #[test]
    fn every_name_is_lowercase_and_unique() {
        for (i, a) in NAMES.iter().enumerate() {
            assert_eq!(a.name, a.name.to_ascii_lowercase());
            for b in &NAMES[i + 1..] {
                assert_ne!(a.name, b.name);
            }
        }
    }
}
