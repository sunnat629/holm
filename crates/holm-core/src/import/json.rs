//! JSON import: an array of flat objects keyed by Holm column names.

use crate::plain::parse_json_rows;

use super::row::{self, RawRow};
use super::{Dialect, ImportBatch, ImportError, MAX_IMPORT_COLUMNS, MAX_IMPORT_ROWS};

/// Reads a JSON import file (already size-checked, UTF-8 and without a BOM).
///
/// Keys are the CSV header names and aliases (trimmed, ASCII case-insensitive). A key
/// that is not a Holm column, or two keys for one column, make the whole file
/// [`ImportError::Malformed`] at the line of that object. `null` is an empty cell.
pub(super) fn parse_json(src: &str) -> Result<ImportBatch, ImportError> {
    let objects = parse_json_rows(src, MAX_IMPORT_ROWS, MAX_IMPORT_COLUMNS)?;
    let mut batch = ImportBatch::new(Dialect::Holm);
    for (i, mut object) in objects.into_iter().enumerate() {
        let malformed = ImportError::Malformed { line: object.line };
        let mut raw = RawRow::default();
        // One bit per Holm column. Fifty-four columns fit in a `u64`.
        let mut seen = 0u64;
        for (key, value) in &mut object.fields {
            let col = row::holm_col(key).ok_or_else(|| malformed.clone())?;
            let shift = col as usize;
            if shift >= 64 {
                return Err(malformed);
            }
            let bit = 1u64 << shift;
            if seen & bit != 0 {
                return Err(malformed);
            }
            seen |= bit;
            if let Some(value) = value {
                raw.put(col, std::mem::take(value));
            }
        }
        batch.push(i + 1, row::build(raw, Dialect::Holm));
    }
    Ok(batch)
}
