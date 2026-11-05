//! Import from a plaintext CSV or JSON file: Holm's own export, or a browser export
//! from Chrome, Firefox or Safari.
//!
//! The file comes from outside Holm and holds passwords, so it is treated as hostile.
//! [`parse`] checks the size, the encoding and the header, then turns each row into a
//! ready item or a [`RowIssue`] that names the row number and the problem, never a
//! value. Nothing is written yet. [`Session::preview_import`] counts what would
//! happen, and [`Session::import`] adds every ready row that is not a duplicate in one
//! change. A row is a duplicate only if it matches an item (or an earlier row) in every
//! user field. If the vault is then too large to save, every new item is taken back;
//! any other save error keeps them in memory, unsaved.
//!
//! Every cell is a wiping buffer from the private `plain` parsers. A value moves out of
//! it into [`Text`] or [`SecretText`](crate::text::SecretText) without a copy, and a
//! cell that is not used (a browser column Holm does not keep, a Safari
//! one-time-password secret) is wiped when dropped.

mod csv;
mod json;
mod row;

use core::fmt;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use zeroize::Zeroizing;

use crate::body::VaultData;
use crate::category::{CategoryId, name_key};
use crate::error::CoreError;
use crate::item::{ItemData, ItemInput, ItemType, Timestamp};
use crate::plain::PlainError;
use crate::rules::{FieldError, MAX_ITEMS};
use crate::session::Session;
use crate::session::items::insert_new;
use crate::store::VaultStore;
use crate::text::{Text, fold};

/// Largest import file, in bytes.
pub const MAX_IMPORT_BYTES: usize = 16 * 1024 * 1024;
/// Most data rows (CSV) or objects (JSON) one import file may hold.
pub const MAX_IMPORT_ROWS: usize = 50_000;
/// Most columns a CSV header (or keys a JSON object) may have.
pub const MAX_IMPORT_COLUMNS: usize = 64;
/// Shown after every import, because the source file is still on disk in plain text.
pub const IMPORT_DELETE_SOURCE_WARNING: &str = "Import finished. The file you imported from is not encrypted. Delete it now, and empty your trash or recycle bin.";

/// The file format to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportFormat {
    /// Comma-separated values with a header row.
    Csv,
    /// One JSON array of flat objects whose values are strings or `null`.
    Json,
}

/// Which program wrote the file, as told by its header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    /// Holm's own columns. Every JSON file is read as this.
    Holm,
    /// A Chrome password export.
    Chrome,
    /// A Firefox password export.
    Firefox,
    /// A Safari password export.
    Safari,
}

/// Why a whole file was refused. No message carries any of the file's content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    /// The file is over [`MAX_IMPORT_BYTES`].
    #[error("the file is too large to import (16 MiB limit)")]
    TooLarge,
    /// The file is not UTF-8 text.
    #[error("the file is not UTF-8 text")]
    NotUtf8,
    /// The file is empty or holds only whitespace.
    #[error("the file is empty")]
    Empty,
    /// The header has columns Holm does not know, or a Holm header has no `title`.
    #[error("the file has {count} column names Holm does not know")]
    UnknownColumns {
        /// How many header names are not Holm columns.
        count: usize,
    },
    /// Two header names mean the same column (after aliases such as `website`).
    #[error("the file names the same column twice")]
    DuplicateColumn,
    /// The header has more than [`MAX_IMPORT_COLUMNS`] columns.
    #[error("the file has too many columns (64 limit)")]
    TooManyColumns,
    /// The file has more than [`MAX_IMPORT_ROWS`] rows.
    #[error("the file has too many rows (50000 limit)")]
    TooManyRows,
    /// The file breaks the CSV or JSON format, or a JSON object has a key Holm does
    /// not know.
    #[error("the file is not valid at line {line}")]
    Malformed {
        /// 1-based physical line.
        line: u64,
    },
}

impl From<PlainError> for ImportError {
    fn from(e: PlainError) -> ImportError {
        match e {
            PlainError::Malformed { line } => ImportError::Malformed { line },
            PlainError::TooManyRows => ImportError::TooManyRows,
            PlainError::TooManyColumns => ImportError::TooManyColumns,
        }
    }
}

/// Why one row was skipped. It names the problem, never a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowProblem {
    /// A field breaks an item rule.
    Field(FieldError),
    /// The `type` cell is not a type Holm knows.
    UnknownType,
    /// A crypto row has no address.
    MissingAddress,
    /// A recovery row has no phrase in its `recovery` cell.
    MissingPhrase,
    /// The row has nothing to import.
    EmptyRow,
    /// The row has more cells than the header.
    ExtraFields,
    /// A secret cell is filled on a row whose type does not use it.
    UnusedField,
    /// The `favourite` cell is not `true`, `false` or empty.
    BadFavourite,
    /// A `created` or `updated` cell is not Unix seconds, or `updated` is earlier.
    BadTimestamp,
}

/// One skipped row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowIssue {
    /// 1-based data row (CSV: not counting the header; JSON: the object's position).
    pub row: usize,
    /// What is wrong with it.
    pub problem: RowProblem,
}

/// A row that passed every check, waiting to be added.
pub(crate) struct ImportRow {
    /// The item, with `category` still `None`; it is matched at preview and import.
    pub(crate) input: ItemInput,
    /// The category name from the file, if the cell was not blank.
    pub(crate) category_name: Option<Text>,
    /// The `created` cell, if given.
    pub(crate) created: Option<Timestamp>,
    /// The `updated` cell, if given.
    pub(crate) updated: Option<Timestamp>,
}

/// A parsed file: ready rows and the issues of the rows that were skipped.
///
/// It has no `Clone`, and its `Debug` shows counts only.
pub struct ImportBatch {
    dialect: Dialect,
    rows: Vec<ImportRow>,
    issues: Vec<RowIssue>,
    otp_ignored: usize,
}

impl ImportBatch {
    fn new(dialect: Dialect) -> ImportBatch {
        ImportBatch {
            dialect,
            rows: Vec::new(),
            issues: Vec::new(),
            otp_ignored: 0,
        }
    }

    /// Adds the outcome of data row `row`.
    fn push(&mut self, row: usize, outcome: Result<ImportRow, RowProblem>) {
        match outcome {
            Ok(r) => self.rows.push(r),
            Err(problem) => self.issues.push(RowIssue { row, problem }),
        }
    }

    /// Which program wrote the file.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// How many rows passed every check (duplicates included).
    #[must_use]
    pub fn ready(&self) -> usize {
        self.rows.len()
    }

    /// The skipped rows, in file order.
    #[must_use]
    pub fn issues(&self) -> &[RowIssue] {
        &self.issues
    }

    /// How many Safari rows had a one-time-password secret. Holm does not store it.
    #[must_use]
    pub fn otp_ignored(&self) -> usize {
        self.otp_ignored
    }
}

/// Shows the dialect and counts, never a value.
impl fmt::Debug for ImportBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportBatch")
            .field("dialect", &self.dialect)
            .field("ready", &self.rows.len())
            .field("issues", &self.issues.len())
            .field("otp_ignored", &self.otp_ignored)
            .finish()
    }
}

/// What [`Session::import`] would do with a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportPreview {
    /// Which program wrote the file.
    pub dialect: Dialect,
    /// Rows that passed every check, duplicates included.
    pub ready: usize,
    /// Rows that will be skipped because of a [`RowIssue`].
    pub issues: usize,
    /// Logins that would be added.
    pub logins: usize,
    /// Crypto addresses that would be added.
    pub crypto: usize,
    /// Recovery phrases that would be added.
    pub phrases: usize,
    /// Secure notes that would be added.
    pub notes: usize,
    /// Rows to add whose category name matches no category; they land in
    /// Uncategorised. Rows with a blank category are not counted here.
    pub unmatched_category_rows: usize,
    /// Ready rows that will be skipped because the vault, or an earlier row of the
    /// file, already has the same item.
    pub duplicates: usize,
    /// Safari one-time-password secrets that will not be stored.
    pub otp_ignored: usize,
}

/// What [`Session::import`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportReport {
    /// Items added.
    pub imported: usize,
    /// Items added with no category (blank or unmatched category cell).
    pub uncategorised: usize,
    /// Ready rows skipped as duplicates.
    pub duplicates: usize,
    /// Rows skipped because of a [`RowIssue`].
    pub skipped: usize,
}

/// Reads an import file. Nothing is written to any vault.
///
/// Checks, in order: the size, UTF-8, one leading byte-order mark is removed, the
/// file is not blank, then the format. A row that breaks a rule becomes a
/// [`RowIssue`]; the rest of the file is still read.
///
/// # Errors
/// The [`ImportError`] for a problem with the whole file.
pub fn parse(bytes: &[u8], format: ImportFormat) -> Result<ImportBatch, ImportError> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::TooLarge);
    }
    let src = core::str::from_utf8(bytes).map_err(|_| ImportError::NotUtf8)?;
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);
    if src.trim().is_empty() {
        return Err(ImportError::Empty);
    }
    match format {
        ImportFormat::Csv => csv::parse_csv(src),
        ImportFormat::Json => json::parse_json(src),
    }
}

/// The hash key of an item's display fields: the folded, trimmed title, the folded
/// username, the folded URLs joined by `\n`, the folded chain and the type, separated
/// by `\0`. A field the type does not have is passed empty.
///
/// Only display fields go in, so no secret is ever hashed. Items with equal keys are
/// then compared field by field (see `same_item`).
pub(crate) fn dedup_key(
    item_type: ItemType,
    title: &str,
    username: &str,
    urls: &[&str],
    chain: &str,
) -> Zeroizing<String> {
    let title = fold(title.trim());
    let username = fold(username);
    let urls: Vec<Zeroizing<String>> = urls.iter().map(|u| fold(u)).collect();
    let chain = fold(chain);
    let tag = match item_type {
        ItemType::Login => "login",
        ItemType::CryptoAddress => "crypto",
        ItemType::RecoveryPhrase => "recovery",
        ItemType::SecureNote => "note",
    };
    // Sized up front so the buffer never reallocates and leaves no unwiped copy.
    let len = title.len()
        + username.len()
        + urls.iter().map(|u| u.len() + 1).sum::<usize>()
        + chain.len()
        + tag.len()
        + 4;
    let mut key = Zeroizing::new(String::with_capacity(len));
    key.push_str(&title);
    key.push('\0');
    key.push_str(&username);
    key.push('\0');
    for (i, u) in urls.iter().enumerate() {
        if i > 0 {
            key.push('\n');
        }
        key.push_str(u);
    }
    key.push('\0');
    key.push_str(&chain);
    key.push('\0');
    key.push_str(tag);
    key
}

/// The dedup key of an item's title and data.
fn key_of(title: &Text, data: &ItemData) -> Zeroizing<String> {
    match data {
        ItemData::Login { username, urls, .. } => {
            let urls: Vec<&str> = urls.iter().map(Text::as_str).collect();
            dedup_key(
                ItemType::Login,
                title.as_str(),
                username.as_str(),
                &urls,
                "",
            )
        }
        ItemData::CryptoAddress { chain, .. } => dedup_key(
            ItemType::CryptoAddress,
            title.as_str(),
            "",
            &[],
            chain.as_str(),
        ),
        other => dedup_key(other.item_type(), title.as_str(), "", &[], ""),
    }
}

/// A dedup key in a hash set. `Zeroizing` has no `Hash`, so this hashes the text.
#[derive(PartialEq, Eq)]
struct Key(Zeroizing<String>);

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state);
    }
}

/// True if two items with equal [`dedup_key`]s are the same in every other user field:
/// the category, and every secret byte for byte (a recovery phrase word by word).
fn same_item(a: (Option<CategoryId>, &ItemData), b: (Option<CategoryId>, &ItemData)) -> bool {
    if a.0 != b.0 {
        return false;
    }
    match (a.1, b.1) {
        (
            ItemData::Login {
                password: p1,
                notes: n1,
                ..
            },
            ItemData::Login {
                password: p2,
                notes: n2,
                ..
            },
        ) => p1.expose() == p2.expose() && n1.expose() == n2.expose(),
        (
            ItemData::CryptoAddress {
                address: a1,
                memo: m1,
                notes: n1,
                ..
            },
            ItemData::CryptoAddress {
                address: a2,
                memo: m2,
                notes: n2,
                ..
            },
        ) => a1.expose() == a2.expose() && m1.expose() == m2.expose() && n1.expose() == n2.expose(),
        (
            ItemData::RecoveryPhrase {
                phrase: w1,
                notes: n1,
            },
            ItemData::RecoveryPhrase {
                phrase: w2,
                notes: n2,
            },
        ) => {
            w1.expose()
                .split_whitespace()
                .eq(w2.expose().split_whitespace())
                && n1.expose() == n2.expose()
        }
        (ItemData::SecureNote { body: b1 }, ItemData::SecureNote { body: b2 }) => {
            b1.expose() == b2.expose()
        }
        _ => false,
    }
}

/// For each row, `true` if it would be added: it is not the same item (in every user
/// field) as any item in the vault, active or in the trash, or any earlier row.
///
/// Items are grouped by the hash of their display fields, and only items in one group
/// are compared, so secrets are compared in place and never hashed or copied.
fn keep_mask(data: &VaultData, rows: &[ImportRow]) -> Vec<bool> {
    type Group<'a> = Vec<(Option<CategoryId>, &'a ItemData)>;
    let mut seen: HashMap<Key, Group<'_>> = HashMap::with_capacity(data.items.len());
    for item in &data.items {
        seen.entry(Key(key_of(&item.title, &item.data)))
            .or_default()
            .push((item.category, &item.data));
    }
    rows.iter()
        .map(|r| {
            let this = (find_category(data, r.category_name.as_ref()), &r.input.data);
            let group = seen
                .entry(Key(key_of(&r.input.title, &r.input.data)))
                .or_default();
            let new = !group.iter().any(|other| same_item(*other, this));
            if new {
                group.push(this);
            }
            new
        })
        .collect()
}

/// The category whose name matches `name` (trimmed, NFC, case-insensitive).
fn find_category(data: &VaultData, name: Option<&Text>) -> Option<CategoryId> {
    let key = name_key(name?.as_str());
    data.categories
        .iter()
        .find(|c| *name_key(c.name.as_str()) == *key)
        .map(|c| c.id)
}

/// Imported times stay between the Unix epoch and now. A missing time uses now,
/// except that `created` cannot be after `updated`.
fn times(
    now: Timestamp,
    created: Option<Timestamp>,
    updated: Option<Timestamp>,
) -> (Timestamp, Timestamp) {
    let now = Timestamp(now.0.max(0));
    let clamp = |t: Timestamp| Timestamp(t.0.clamp(0, now.0));
    let created = created.map(clamp);
    let updated = updated.map(clamp);
    match (created, updated) {
        (Some(c), Some(u)) => (c, u),
        (Some(c), None) => (c, c.max(now)),
        (None, Some(u)) => (u.min(now), u),
        (None, None) => (now, now),
    }
}

impl<S: VaultStore> Session<S> {
    /// Counts what [`Session::import`] would do with `batch`. Changes nothing.
    ///
    /// # Errors
    /// [`CoreError::Locked`].
    pub fn preview_import(&self, batch: &ImportBatch) -> Result<ImportPreview, CoreError> {
        let data = &self.unlocked()?.data;
        let keep = keep_mask(data, &batch.rows);
        let mut p = ImportPreview {
            dialect: batch.dialect,
            ready: batch.rows.len(),
            issues: batch.issues.len(),
            logins: 0,
            crypto: 0,
            phrases: 0,
            notes: 0,
            unmatched_category_rows: 0,
            duplicates: 0,
            otp_ignored: batch.otp_ignored,
        };
        for (row, keep) in batch.rows.iter().zip(keep) {
            if !keep {
                p.duplicates += 1;
                continue;
            }
            match row.input.data.item_type() {
                ItemType::Login => p.logins += 1,
                ItemType::CryptoAddress => p.crypto += 1,
                ItemType::RecoveryPhrase => p.phrases += 1,
                ItemType::SecureNote => p.notes += 1,
            }
            if row.category_name.is_some()
                && find_category(data, row.category_name.as_ref()).is_none()
            {
                p.unmatched_category_rows += 1;
            }
        }
        Ok(p)
    }

    /// Adds every ready row of `batch` that is not a duplicate, as one change.
    ///
    /// Duplicates are dropped first: rows identical in type, title, username, URLs,
    /// chain, category and every secret to an item in the vault (trash included) or to
    /// an earlier row. If the rest would take the vault over [`MAX_ITEMS`], nothing is
    /// added. Categories are matched by name and never created. If the vault then has no
    /// room to save, every added item is taken back.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::TooManyItems`] (nothing added), or the
    /// errors of saving. [`CoreError::Vault`] with `TooLargeToSave` means nothing was
    /// added. Any other save error leaves the items added in memory but not saved, and
    /// the session dirty.
    pub fn import(&mut self, batch: ImportBatch) -> Result<ImportReport, CoreError> {
        self.unlocked()?;
        let now = self.now_unix();
        let ImportBatch { rows, issues, .. } = batch;
        let data = &mut self.unlocked_mut()?.data;
        let keep = keep_mask(data, &rows);
        let remaining = keep.iter().filter(|k| **k).count();
        let duplicates = rows.len() - remaining;
        if data.items.len() + remaining > MAX_ITEMS {
            return Err(CoreError::TooManyItems);
        }
        let start = data.items.len();
        let mut uncategorised = 0;
        // A dropped duplicate row wipes its fields as it goes out of scope.
        for (row, _) in rows.into_iter().zip(keep).filter(|(_, k)| *k) {
            let ImportRow {
                mut input,
                category_name,
                created,
                updated,
            } = row;
            input.category = find_category(data, category_name.as_ref());
            if input.category.is_none() {
                uncategorised += 1;
            }
            if let Err(e) = insert_new(data, input, now) {
                data.items.truncate(start);
                return Err(e);
            }
            let (c, u) = times(now, created, updated);
            if let Some(item) = data.items.last_mut() {
                item.created = c;
                item.updated = u;
            }
        }
        self.commit_or_undo(move |d| d.items.truncate(start))?;
        Ok(ImportReport {
            imported: remaining,
            uncategorised,
            duplicates,
            skipped: issues.len(),
        })
    }
}

#[cfg(test)]
mod tests;
