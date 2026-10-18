//! Column names, and turning one row of cells into an item.
//!
//! The rules here are the same for CSV and JSON. A row's problem is a
//! [`RowProblem`], which names the problem and never a value. Holm never guesses
//! where a secret goes: a phrase comes only from the `recovery` column, and a secret
//! cell the row's type does not use is an error, not silently dropped.

use crate::item::{ItemData, ItemInput, Timestamp};
use crate::plain::Cell;
use crate::rules::MAX_URLS;
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
}

/// How many Holm columns there are.
const COLS: usize = 14;

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

const NAMES: [Name; 26] = [
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
#[derive(Default)]
pub(super) struct RawRow {
    cells: [Cell; COLS],
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
    let input = ItemInput {
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
