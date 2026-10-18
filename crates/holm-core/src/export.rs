//! Plaintext CSV export of every item outside the Trash.
//!
//! The export file is the one place where Holm writes secrets in plain text, and only
//! because the user asked for it. So [`Session::export_csv`] checks the master
//! password first (through the throttle), the caller shows [`EXPORT_WARNING`] and asks
//! for a confirmation, and the bytes come back in one wiping [`SecretBuf`].
//!
//! The text is measured before it is written: every cell's quoted length is added up
//! first, the buffer is allocated once at that size, and then it is filled without
//! growing. A growing buffer would move its bytes and leave an unwiped copy of every
//! password behind in freed memory.
//!
//! Every cell is quoted and written verbatim. Holm does not escape cells that start
//! with `=`, `+`, `-` or `@` (spreadsheet formulas), because that would change real
//! passwords and break the import back into Holm or another manager. The warning says
//! not to open the file in a spreadsheet app instead.

use holm_crypto::{MasterPassword, SecretBuf};
use zeroize::Zeroizing;

use crate::category::Category;
use crate::error::CoreError;
use crate::item::{Item, ItemData};
use crate::plain::{ROW_END, push_quoted, quoted_len};
use crate::search::cmp_title_asc;
use crate::session::Session;
use crate::store::VaultStore;
use crate::text::Text;

/// Shown before every export, before the master password is asked for.
pub const EXPORT_WARNING: &str = "This file will hold every password in this vault in plain text. Anyone who can read it can use them. Save it only on an encrypted disk, do not open it in a spreadsheet app, and delete it as soon as you are done.";

/// The export header: the 11 import columns, then the three metadata columns.
pub const EXPORT_COLUMNS: [&str; 14] = [
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
        let data = &self.unlocked()?.data;
        let mut items: Vec<&Item> = data.items.iter().filter(|i| i.trashed.is_none()).collect();
        items.sort_by(|a, b| cmp_title_asc(a, b));
        Ok(write_csv(&items, &data.categories))
    }
}

/// Writes the header and one row per item, in the order given.
pub(crate) fn write_csv(items: &[&Item], categories: &[Category]) -> SecretBuf {
    let mut text = build(items, categories);
    // Moves the bytes out without a copy; the emptied `String` left behind owns nothing.
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

/// Calls `f` with the 14 cells of `item`'s row, in [`EXPORT_COLUMNS`] order. The few
/// cells built here (the joined URLs and the numbers) are wiped when `f` returns.
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
    f(&[
        item.title.as_str(),
        username,
        password,
        urls.as_str(),
        notes,
        category,
        kind,
        chain,
        address,
        memo,
        recovery,
        favourite,
        created.as_str(),
        updated.as_str(),
    ])
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
