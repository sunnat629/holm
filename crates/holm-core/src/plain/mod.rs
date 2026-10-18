//! Holm's own CSV and JSON code for plaintext import and export.
//!
//! Import files come from outside Holm and hold passwords, so these readers treat
//! every byte as hostile: they work on byte offsets into the source `&str`, never
//! recurse, and fail with a line number only, never with the text they saw.
//!
//! Every decoded cell is a [`Cell`], a `Zeroizing<String>` that is allocated once
//! at its final size (CSV) or at an upper bound (JSON) and then filled without
//! growing, so no reallocation leaves an unwiped copy of a password behind.

mod csv;
mod json;

pub(crate) use csv::{CsvReader, ROW_END, push_quoted, quoted_len};
pub(crate) use json::parse_json_rows;
// Callers use these through method results and never name them; the tests do.
#[cfg(test)]
pub(crate) use csv::Record;
#[cfg(test)]
pub(crate) use json::JsonObject;

use zeroize::Zeroizing;

/// One decoded CSV cell, JSON key or JSON string value. Wiped when dropped.
pub(crate) type Cell = Zeroizing<String>;

/// Why a CSV or JSON source was refused. No variant carries any of the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlainError {
    /// The text breaks the format. `line` is the 1-based physical line where the
    /// bad CSV cell starts, or where the JSON parser stopped.
    Malformed {
        /// 1-based physical line.
        line: u64,
    },
    /// More JSON objects than the caller allows.
    TooManyRows,
    /// More keys in one JSON object than the caller allows.
    TooManyColumns,
}
