//! CSV import: the header decides the dialect and where each column's cells go.

use std::collections::HashMap;

use crate::plain::{Cell, CsvReader};

use super::row::{self, Col, RawRow};
use super::{Dialect, ImportBatch, ImportError, MAX_IMPORT_COLUMNS, MAX_IMPORT_ROWS, RowProblem};

/// Where the cells of one header column go.
#[derive(Clone, Copy)]
enum Slot {
    /// Into this Holm column.
    Col(Col),
    /// A Safari one-time-password secret: counted, never stored.
    Otp,
    /// A browser column Holm does not keep. The cell is wiped when dropped.
    Ignore,
}

/// Firefox: exactly these columns.
const FIREFOX: [&str; 9] = [
    "url",
    "username",
    "password",
    "httprealm",
    "formactionorigin",
    "guid",
    "timecreated",
    "timelastused",
    "timepasswordchanged",
];
/// Safari: these columns, plus an optional `notes`.
const SAFARI: [&str; 5] = ["title", "url", "username", "password", "otpauth"];
/// Chrome: these columns, plus an optional `note`.
const CHROME: [&str; 4] = ["name", "url", "username", "password"];

/// The dialect and, for each header column, where its cells go.
struct Header {
    dialect: Dialect,
    slots: Vec<Slot>,
}

/// Reads the header row. The caller has already checked the column count.
///
/// Names are trimmed and compared ASCII case-insensitively against static tables, so
/// no copy of a header cell is made (a file with no header row would have a password
/// here).
fn read_header(cells: &[Cell]) -> Result<Header, ImportError> {
    // Canonical name -> column position. Aliases share a canonical name, so `url`
    // and `website` collide here.
    let mut known: HashMap<&'static str, usize> = HashMap::with_capacity(cells.len());
    let mut unknown: Vec<&str> = Vec::new();
    for (i, cell) in cells.iter().enumerate() {
        match row::canonical(cell) {
            Some(name) => {
                if known.insert(name, i).is_some() {
                    return Err(ImportError::DuplicateColumn);
                }
            }
            None => {
                let name = cell.trim();
                if unknown.iter().any(|u| u.eq_ignore_ascii_case(name)) {
                    return Err(ImportError::DuplicateColumn);
                }
                unknown.push(name);
            }
        }
    }
    // Exactly `required`, plus at most the `optional` name.
    let is = |required: &[&str], optional: Option<&str>| {
        unknown.is_empty()
            && required.iter().all(|n| known.contains_key(n))
            && known
                .keys()
                .all(|k| required.contains(k) || optional == Some(*k))
    };
    let not_holm = unknown.len() + known.keys().filter(|k| row::holm_col(k).is_none()).count();
    let dialect = if is(&FIREFOX, None) {
        Dialect::Firefox
    } else if is(&SAFARI, Some("notes")) {
        Dialect::Safari
    } else if is(&CHROME, Some("note")) {
        Dialect::Chrome
    } else if not_holm == 0 && known.contains_key("title") {
        Dialect::Holm
    } else {
        return Err(ImportError::UnknownColumns { count: not_holm });
    };
    let slots = cells
        .iter()
        .map(|cell| match (dialect, row::canonical(cell)) {
            (Dialect::Chrome, Some("name")) => Slot::Col(Col::Title),
            (Dialect::Chrome, Some("note")) => Slot::Col(Col::Notes),
            (Dialect::Safari, Some("otpauth")) => Slot::Otp,
            _ => row::holm_col(cell).map_or(Slot::Ignore, Slot::Col),
        })
        .collect();
    Ok(Header { dialect, slots })
}

/// Reads a CSV import file (already size-checked, UTF-8 and without a BOM).
pub(super) fn parse_csv(src: &str) -> Result<ImportBatch, ImportError> {
    let mut reader = CsvReader::new(src);
    let mut cells: Vec<Cell> = Vec::new();
    let Some(head) = reader.next_record(&mut cells, MAX_IMPORT_COLUMNS)? else {
        return Err(ImportError::Empty);
    };
    if head.cells_seen > MAX_IMPORT_COLUMNS {
        return Err(ImportError::TooManyColumns);
    }
    let header = read_header(&cells)?;
    let width = header.slots.len();
    let mut batch = ImportBatch::new(header.dialect);
    let mut row = 0;
    // One cell past the header width is kept, so an over-long row is seen.
    while let Some(record) = reader.next_record(&mut cells, width + 1)? {
        row += 1;
        if row > MAX_IMPORT_ROWS {
            return Err(ImportError::TooManyRows);
        }
        if record.cells_seen > width {
            batch.push(row, Err(RowProblem::ExtraFields));
            continue;
        }
        // Missing cells at the end stay empty.
        let mut raw = RawRow::default();
        let mut otp = false;
        for (cell, slot) in cells.iter_mut().zip(&header.slots) {
            match *slot {
                Slot::Col(col) => raw.put(col, std::mem::take(cell)),
                Slot::Otp => otp |= !cell.trim().is_empty(),
                Slot::Ignore => {}
            }
        }
        if otp {
            batch.otp_ignored += 1;
        }
        batch.push(row, row::build(raw, header.dialect));
    }
    Ok(batch)
}
