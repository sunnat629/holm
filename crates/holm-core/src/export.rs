//! Plaintext CSV and JSON export of every item outside the Trash.
//!
//! The export file is the one place where Holm writes secrets in plain text, and only
//! because the user asked for it. So [`Session::export_csv`] and [`Session::export_json`]
//! check the master password first (through the throttle), the caller shows
//! [`EXPORT_WARNING`] and asks for a confirmation, and the bytes come back in one
//! wiping [`SecretBuf`].
//!
//! The text is measured before it is written: every cell's quoted length is added up
//! first, the buffer is allocated once at that size, and then it is filled without
//! growing. A growing buffer would move its bytes and leave an unwiped copy of every
//! password behind in freed memory. A custom value is borrowed for that fill. A secret
//! is not copied into a second `String`.
//!
//! Every cell is quoted and written verbatim. Holm does not escape cells that start
//! with `=`, `+`, `-` or `@` (spreadsheet formulas), because that would change real
//! passwords and break the import back into Holm or another manager. The warning says
//! not to open the file in a spreadsheet app instead.
//!
//! Custom fields are four cells per slot, `field1_label` through `field10_expiry`, on
//! the same flat row. JSON uses those names as keys. It does not nest a field object.

use holm_crypto::{MasterPassword, SecretBuf};
use zeroize::Zeroizing;

use crate::category::Category;
use crate::error::CoreError;
use crate::fields::{FieldKind, FieldValue, codes_to_cell, format_date};
use crate::item::{Item, ItemData};
use crate::plain::{ROW_END, json_string_len, push_json_string, push_quoted, quoted_len};
use crate::rules::MAX_CUSTOM_FIELDS;
use crate::search::cmp_title_asc;
use crate::session::Session;
use crate::store::VaultStore;
use crate::text::Text;

/// Shown before every export, before the master password is asked for.
pub const EXPORT_WARNING: &str = "This file will hold every password in this vault in plain text. Anyone who can read it can use them. Save it only on an encrypted disk, do not open it in a spreadsheet app, and delete it as soon as you are done.";

/// Columns Holm exported before custom fields. Their names and order stay.
const BUILTIN_COLUMNS: usize = 14;

/// The export header: the 11 import columns, the three metadata columns, then four
/// cells for each custom-field slot.
pub const EXPORT_COLUMNS: [&str; BUILTIN_COLUMNS + MAX_CUSTOM_FIELDS * 4] = [
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
    "field1_label",
    "field1_kind",
    "field1_value",
    "field1_expiry",
    "field2_label",
    "field2_kind",
    "field2_value",
    "field2_expiry",
    "field3_label",
    "field3_kind",
    "field3_value",
    "field3_expiry",
    "field4_label",
    "field4_kind",
    "field4_value",
    "field4_expiry",
    "field5_label",
    "field5_kind",
    "field5_value",
    "field5_expiry",
    "field6_label",
    "field6_kind",
    "field6_value",
    "field6_expiry",
    "field7_label",
    "field7_kind",
    "field7_value",
    "field7_expiry",
    "field8_label",
    "field8_kind",
    "field8_value",
    "field8_expiry",
    "field9_label",
    "field9_kind",
    "field9_value",
    "field9_expiry",
    "field10_label",
    "field10_kind",
    "field10_value",
    "field10_expiry",
];

const _: () = assert!(BUILTIN_COLUMNS + MAX_CUSTOM_FIELDS * 4 == EXPORT_COLUMNS.len());

impl<S: VaultStore> Session<S> {
    /// Every item outside the Trash as CSV, after the master password is checked
    /// again (throttled).
    ///
    /// Rows follow the list order (folded title, then id). The caller must show
    /// [`EXPORT_WARNING`] and get a confirmation first.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Throttled`], [`CoreError::WrongPassword`],
    /// or [`CoreError::Vault`].
    pub fn export_csv(&mut self, password: &MasterPassword) -> Result<SecretBuf, CoreError> {
        self.check_password(password)?;
        let (items, categories) = listed(self)?;
        Ok(write_csv(&items, categories))
    }

    /// Every item outside the Trash as one JSON array of flat string objects, after
    /// the master password is checked again (throttled).
    ///
    /// Keys are [`EXPORT_COLUMNS`] in that order. Items follow the same title order as
    /// [`Session::export_csv`]. An empty cell is an empty string. The caller must show
    /// [`EXPORT_WARNING`] and get a confirmation first.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Throttled`], [`CoreError::WrongPassword`],
    /// or [`CoreError::Vault`].
    pub fn export_json(&mut self, password: &MasterPassword) -> Result<SecretBuf, CoreError> {
        self.check_password(password)?;
        let (items, categories) = listed(self)?;
        Ok(write_json(&items, categories))
    }
}

/// Items outside the Trash, in list order, and the category list they name.
fn listed<S: VaultStore>(session: &Session<S>) -> Result<(Vec<&Item>, &[Category]), CoreError> {
    let data = &session.unlocked()?.data;
    let mut items: Vec<&Item> = data.items.iter().filter(|i| i.trashed.is_none()).collect();
    items.sort_by(|a, b| cmp_title_asc(a, b));
    Ok((items, &data.categories))
}

/// Writes the header and one row per item, in the order given.
pub(crate) fn write_csv(items: &[&Item], categories: &[Category]) -> SecretBuf {
    let mut text = build(items, categories);
    // Moves the bytes out without a copy; the emptied `String` left behind owns nothing.
    SecretBuf::from_vec(core::mem::take(&mut *text).into_bytes())
}

/// Writes one JSON array of flat objects, in the order given.
pub(crate) fn write_json(items: &[&Item], categories: &[Category]) -> SecretBuf {
    let mut text = build_json(items, categories);
    SecretBuf::from_vec(core::mem::take(&mut *text).into_bytes())
}

/// The CSV text in a buffer allocated once at its final size.
fn build(items: &[&Item], categories: &[Category]) -> Zeroizing<String> {
    // Measure: every quoted cell, the commas between cells and the row ends.
    let mut total = row_len(&EXPORT_COLUMNS);
    for item in items {
        total = total.saturating_add(with_cells(item, categories, row_len));
    }

    // Fill: one allocation, never grown, so no unwiped copy is left behind.
    let mut out = Zeroizing::new(String::with_capacity(total));
    push_row(&mut out, &EXPORT_COLUMNS);
    for item in items {
        with_cells(item, categories, |cells| push_row(&mut out, cells));
    }
    assert_eq!(out.len(), total, "export measure and fill disagree");
    out
}

/// The JSON text in a buffer allocated once at its final size.
fn build_json(items: &[&Item], categories: &[Category]) -> Zeroizing<String> {
    let mut total: usize = 2;
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            total = total.saturating_add(1);
        }
        total = total.saturating_add(with_cells(item, categories, json_row_len));
    }
    let mut out = Zeroizing::new(String::with_capacity(total));
    push_fitting(&mut out, "[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            push_fitting(&mut out, ",");
        }
        with_cells(item, categories, |cells| push_json_row(&mut out, cells));
    }
    push_fitting(&mut out, "]");
    assert_eq!(out.len(), total, "export measure and fill disagree");
    out
}

/// The bytes [`push_row`] writes for `cells`.
fn row_len(cells: &[&str; COLUMNS]) -> usize {
    cells
        .iter()
        .fold(SEPARATORS, |sum, cell| sum.saturating_add(quoted_len(cell)))
}

/// Appends one row: every cell quoted, `,` between cells, then [`ROW_END`].
fn push_row(out: &mut String, cells: &[&str; COLUMNS]) {
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            push_fitting(out, ",");
        }
        push_quoted(out, cell);
    }
    push_fitting(out, ROW_END);
}

/// The bytes [`push_json_row`] writes for `cells`.
fn json_row_len(cells: &[&str; COLUMNS]) -> usize {
    let mut n: usize = 2;
    for (i, (key, cell)) in EXPORT_COLUMNS.iter().zip(cells.iter()).enumerate() {
        if i > 0 {
            n = n.saturating_add(1);
        }
        // `"key":` plus the quoted value.
        n = n.saturating_add(key.len().saturating_add(3));
        n = n.saturating_add(json_string_len(cell));
    }
    n
}

/// Appends one object: keys in [`EXPORT_COLUMNS`] order, every value a string.
fn push_json_row(out: &mut String, cells: &[&str; COLUMNS]) {
    push_fitting(out, "{");
    for (i, (key, cell)) in EXPORT_COLUMNS.iter().zip(cells.iter()).enumerate() {
        if i > 0 {
            push_fitting(out, ",");
        }
        push_fitting(out, "\"");
        push_fitting(out, key);
        push_fitting(out, "\":");
        push_json_string(out, cell);
    }
    push_fitting(out, "}");
}

/// Appends `s`, which must fit in the room `out` already has.
fn push_fitting(out: &mut String, s: &str) {
    assert!(
        out.capacity() - out.len() >= s.len(),
        "export buffer too small"
    );
    out.push_str(s);
}

const COLUMNS: usize = EXPORT_COLUMNS.len();

/// The `,` between the cells of one row, plus [`ROW_END`].
const SEPARATORS: usize = COLUMNS - 1 + ROW_END.len();

/// Calls `f` with the cells of `item`'s row, in [`EXPORT_COLUMNS`] order. The few
/// cells built here (the joined URLs, the numbers, the date text and the recovery
/// codes cells) are wiped when `f` returns. Other secret values are borrowed, not
/// copied.
fn with_cells<R>(item: &Item, categories: &[Category], f: impl FnOnce(&[&str; COLUMNS]) -> R) -> R {
    let category = item
        .category
        .and_then(|id| categories.iter().find(|c| c.id() == id))
        .map_or("", Category::name);
    let favourite = if item.favourite { "true" } else { "false" };
    let created = Zeroizing::new(item.created.0.to_string());
    let updated = Zeroizing::new(item.updated.0.to_string());
    let mut urls = Zeroizing::new(String::new());
    let (kind, username, password, notes, chain, address, memo, recovery) = match &item.data {
        ItemData::Login {
            username,
            password,
            urls: list,
            notes,
        } => {
            urls = join_lines(list);
            (
                "login",
                username.as_str(),
                password.expose(),
                notes.expose(),
                "",
                "",
                "",
                "",
            )
        }
        ItemData::SecureNote { body } => ("note", "", "", body.expose(), "", "", "", ""),
        ItemData::CryptoAddress {
            chain,
            address,
            memo,
            notes,
        } => (
            "crypto",
            "",
            "",
            notes.expose(),
            chain.as_str(),
            address.expose(),
            memo.expose(),
            "",
        ),
        ItemData::RecoveryPhrase { phrase, notes } => (
            "recovery",
            "",
            "",
            notes.expose(),
            "",
            "",
            "",
            phrase.expose(),
        ),
    };
    let fields = item.fields();
    let mut value_dates: [Zeroizing<String>; MAX_CUSTOM_FIELDS] = Default::default();
    let mut value_codes: [Zeroizing<String>; MAX_CUSTOM_FIELDS] = Default::default();
    let mut expiry_dates: [Zeroizing<String>; MAX_CUSTOM_FIELDS] = Default::default();
    for (i, field) in fields.iter().enumerate() {
        match field.value() {
            FieldValue::Date(date) => value_dates[i] = write_date(*date),
            FieldValue::RecoveryCodes(codes) => value_codes[i] = codes_to_cell(codes),
            _ => {}
        }
        if let Some(date) = field.expiry() {
            expiry_dates[i] = write_date(date);
        }
    }
    let mut cells = [""; COLUMNS];
    cells[0] = item.title.as_str();
    cells[1] = username;
    cells[2] = password;
    cells[3] = urls.as_str();
    cells[4] = notes;
    cells[5] = category;
    cells[6] = kind;
    cells[7] = chain;
    cells[8] = address;
    cells[9] = memo;
    cells[10] = recovery;
    cells[11] = favourite;
    cells[12] = created.as_str();
    cells[13] = updated.as_str();
    for (i, field) in fields.iter().enumerate() {
        let base = BUILTIN_COLUMNS + i * 4;
        cells[base] = field.label();
        cells[base + 1] = kind_label(field.kind());
        cells[base + 2] = match field.value() {
            FieldValue::Text(text) => text.as_str(),
            FieldValue::Secret(text) | FieldValue::MultilineSecret(text) => text.expose(),
            FieldValue::Date(_) => value_dates[i].as_str(),
            FieldValue::RecoveryCodes(_) => value_codes[i].as_str(),
        };
        if field.expiry().is_some() {
            cells[base + 3] = expiry_dates[i].as_str();
        }
    }
    f(&cells)
}

/// Lower-case kind cell. Import accepts any ASCII case of these five words.
fn kind_label(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Text => "text",
        FieldKind::Secret => "secret",
        FieldKind::MultilineSecret => "multiline",
        FieldKind::Date => "date",
        FieldKind::RecoveryCodes => "codes",
    }
}

/// Ten ASCII bytes for `date`, in a buffer that is wiped on drop.
fn write_date(date: crate::fields::CalendarDate) -> Zeroizing<String> {
    let bytes = format_date(date);
    let mut out = Zeroizing::new(String::with_capacity(bytes.len()));
    for byte in bytes {
        out.push(char::from(byte));
    }
    out
}

/// `urls` joined by `\n`, in a buffer allocated once at its final size.
fn join_lines(urls: &[Text]) -> Zeroizing<String> {
    let len = urls.iter().fold(urls.len().saturating_sub(1), |sum, u| {
        sum.saturating_add(u.as_str().len())
    });
    let mut out = Zeroizing::new(String::with_capacity(len));
    for (i, url) in urls.iter().enumerate() {
        if i > 0 {
            push_fitting(&mut out, "\n");
        }
        push_fitting(&mut out, url.as_str());
    }
    out
}

#[cfg(test)]
mod tests;
